package graylogd

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"
)

type GelfLog struct {
	Version   string  `json:"version"`
	Host      string  `json:"host"`
	ShortMsg  string  `json:"short_message"`
	FullMsg   string  `json:"full_message"`
	Timestamp float64 `json:"timestamp,string"`
	Level     int     `json:"level"`
	Facility  string  `json:"facility"`
	Line      int     `json:"line"`
	File      string  `json:"file"`
}

type Config struct {
	ListenAddr string

	// handle raw message, HandleGELF wouldn't be called if HandleRaw is setted
	HandleRaw func([]byte)

	// handle GELF message
	HandleGELF func(*GelfLog, map[string]interface{})

	HandleError func(*net.UDPAddr, error)
}

type chunkMsg struct {
	id         string
	chunks     [][]byte
	count      int
	size       int
	fstPktTime int64
	deleted    bool
	sync.Mutex
}

type Graylogd struct {
	Config
	chunkCleanChan chan *chunkMsg
	chunkMsgs      map[string]*chunkMsg
	chunklock      sync.Mutex
	conn           *net.UDPConn

	shouldClose bool
}

func NewGraylogd(conf Config) (srv *Graylogd, err error) {

	return &Graylogd{
		Config:    conf,
		chunkMsgs: make(map[string]*chunkMsg),

		// 500000 * 8 = 3.8M
		// assume all logs are in chunked,
		// and the size of chunk is 1.5K, server can serve 1.5K * 500000 in 5s,
		// means 150MBps compressed data in worst
		chunkCleanChan: make(chan *chunkMsg, 300000),
	}, nil
}

func (srv *Graylogd) Run() (err error) {

	addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}

	srv.conn = conn

	go srv.cleanTimeoutChunk()
	go func() {
		// 1024*160 ?
		buf := make([]byte, 1024*160)
		for {
			if srv.shouldClose {
				break
			}
			n, addr, err := conn.ReadFromUDP(buf)
			var nbuf []byte = nil
			if err == nil {
				nbuf = make([]byte, n)
				copy(nbuf, buf[:n])
			}
			go srv.serveMsg(err, addr, nbuf)
		}
	}()

	return
}

func (srv *Graylogd) serveMsg(err error, addr *net.UDPAddr, nbuf []byte) {

	if err != nil {
		srv.handleError(addr, err)
		return
	}

	nb, err := srv.parseBuf(nbuf)
	if err != nil {
		srv.handleError(addr, err)
		return
	}
	if nb == nil {
		// chunked msg
		return
	}

	// born a new message
	err = srv.handleMsg(nb)
	if err != nil {
		srv.handleError(addr, err)
	}
}

func (srv *Graylogd) handleError(addr *net.UDPAddr, err error) {
	if srv.HandleError != nil {
		srv.HandleError(addr, err)
	}
}

func (srv *Graylogd) handleMsg(b []byte) error {
	if srv.HandleRaw != nil {
		srv.HandleRaw(b)
	} else {
		var gelf GelfLog
		err := json.Unmarshal(b, &gelf)
		if err != nil {
			return err
		}
		if gelf.Timestamp <= 0 {
			gelf.Timestamp = float64(time.Now().UnixNano()) / float64(time.Second)
		}

		var v map[string]interface{}
		err = json.Unmarshal(b, &v)
		if err != nil {
			return err
		}

		delete(v, "version")
		delete(v, "host")
		delete(v, "short_message")
		delete(v, "full_message")
		delete(v, "timestamp")
		delete(v, "level")
		delete(v, "facility")
		delete(v, "line")
		delete(v, "file")
		delete(v, "_id")

		srv.HandleGELF(&gelf, v)
	}
	return nil
}

func (srv *Graylogd) Close() (err error) {
	if srv.conn == nil {
		return nil
	}
	err = srv.conn.Close()
	srv.shouldClose = true
	return
}

const (
	// According to https://www.graylog.org/resources/gelf/
	// All chunks MUST arrive within 5 seconds or the server will discard all already arrived and still arriving chunks.
	discardTime = 5 * time.Second
)

func (srv *Graylogd) cleanTimeoutChunk() {

	for msg := range srv.chunkCleanChan {
		if msg.deleted {
			continue
		}
		now := time.Now().UnixNano()
		remain := discardTime - time.Duration(now-msg.fstPktTime)
		if remain > 0 {
			time.Sleep(remain)
		}

		if !msg.deleted {
			srv.chunklock.Lock()
			delete(srv.chunkMsgs, msg.id)
			srv.chunklock.Unlock()
		}
	}
}

func (srv *Graylogd) parseBuf(buf []byte) (b []byte, err error) {

	switch detect((buf)) {
	case payloadPlain:
		return buf, nil
	case payloadGzip:
		r, err1 := gzip.NewReader(bytes.NewReader(buf))
		if err1 != nil {
			return nil, err1
		}
		b, err = ioutil.ReadAll(r)
		return
	case payloadZlib:
		r, err1 := zlib.NewReader(bytes.NewReader(buf))
		if err1 != nil {
			return nil, err1
		}
		b, err = ioutil.ReadAll(r)
		return
	case payloadChunked:
		// parse chunked
		nbuf, err := srv.parseChunk(buf)
		if err != nil {
			return nil, err
		}
		if nbuf == nil {
			return nil, nil
		}
		return srv.parseBuf(nbuf)
	default:
		return nil, errors.New("unknown")
	}
}

func (srv *Graylogd) parseChunk(buf []byte) ([]byte, error) {

	msgId := string(buf[3:10])
	seqNum := int(buf[10])
	seqCount := int(buf[11])
	payload := buf[12:]

	if seqNum >= seqCount {
		return nil, fmt.Errorf("invalid seqNum(%d) with seqCount(%d)", seqNum, seqCount)
	}

	srv.chunklock.Lock()
	msg, ok := srv.chunkMsgs[msgId]
	if !ok {
		msg = &chunkMsg{
			id:         msgId,
			chunks:     make([][]byte, seqCount),
			fstPktTime: time.Now().UnixNano(),
		}
		srv.chunkMsgs[msgId] = msg

		// add to channel, for timeout and delete
		srv.chunkCleanChan <- msg
	}
	srv.chunklock.Unlock()

	msg.Lock()
	defer msg.Unlock()

	if msg.chunks[seqNum] == nil {
		msg.chunks[seqNum] = payload
		msg.count += 1
		msg.size += len(payload)
		if msg.count == len(msg.chunks) {
			srv.chunklock.Lock()
			delete(srv.chunkMsgs, msgId)
			msg.deleted = true
			srv.chunklock.Unlock()

			var rst = make([]byte, 0, msg.size)
			for _, b := range msg.chunks {
				rst = append(rst, b...)
			}
			return rst, nil
		}
	}

	return nil, nil
}

type payloadType uint8

const (
	payloadChunked payloadType = iota
	payloadGzip
	payloadZlib
	payloadPlain
)

func detect(b []byte) payloadType {

	if len(b) < 2 {
		return payloadPlain
	}
	switch {
	case b[0] == 0x1e && b[1] == 0x0f:
		return payloadChunked
	case b[0] == 0x1f && b[1] == 0x8b:
		// gzip first two bytes: 0x1f 0x8b
		// https://tools.ietf.org/rfc/rfc6713.txt
		return payloadGzip
	case (b[0]<<4 == 0x80) && (b[0]>>4 <= 7) && (binary.BigEndian.Uint16(b[:2])%31 == 0):
		// zlib first byte: 0x08, 0x18, ..., 0x78
		// The first two bytes, when interpreted as an unsigned 16-bit number in big-endian byte order,
		// contain a value that is a multiple of 31.
		// https://tools.ietf.org/rfc/rfc6713.txt
		return payloadZlib
	default:
		return payloadPlain
	}
}
