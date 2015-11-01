package graylogd

import (
	"crypto/rand"
	"encoding/json"
	"github.com/robertkowalski/graylog-golang"
	"github.com/stretchr/testify/assert"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRaw(t *testing.T) {

	ast := assert.New(t)

	waitChan := make(chan bool, 1)
	var realB []byte
	daeCfg := Config{
		ListenAddr: ":8948",
		HandleRaw: func(b []byte) {
			ast.Equal(realB, b)
			waitChan <- true
		},
		HandleGELF: func(gelf *GelfLog, addi map[string]interface{}) {
			t.Fatal("shouldn't be called")
		},
		HandleError: func(addr *net.UDPAddr, err error) {
			t.Fatal("should be no error", err)
		},
	}
	logd, err := NewGraylogd(daeCfg)
	ast.Nil(err)
	defer logd.Close()
	ast.Nil(logd.Run())

	client := gelf.New(gelf.Config{
		GraylogPort:     8948,
		GraylogHostname: "127.0.0.1",
	})

	counts := []int{0, 1, 2, 4, 8, 64, 128, 516, 1 << 10, 1 << 12, 1 << 15}
	for _, n := range counts {
		realB = make([]byte, n)
		_, err := rand.Read(realB)
		ast.Nil(err)

		client.Log(string(realB))
		<-waitChan
	}
}

func TestGELF(t *testing.T) {

	ast := assert.New(t)

	waitChan := make(chan bool, 1)
	var realLog GelfLog
	var realAddi map[string]interface{}
	daeCfg := Config{
		ListenAddr: ":8948",
		HandleGELF: func(gelf *GelfLog, addi map[string]interface{}) {
			ast.Equal(realLog, *gelf)
			ast.Equal(realAddi, addi)
			for k, _ := range addi {
				ast.True(k != "_id")
				ast.True(strings.HasPrefix(k, "_"))
			}
			waitChan <- true
		},
		HandleError: func(addr *net.UDPAddr, err error) {
			t.Fatal("should be no error", err)
		},
	}
	logd, err := NewGraylogd(daeCfg)
	ast.Nil(err)
	defer logd.Close()
	ast.Nil(logd.Run())

	client := gelf.New(gelf.Config{
		GraylogPort:     8948,
		GraylogHostname: "127.0.0.1",
	})

	realLog = GelfLog{
		Version:   "1.0",
		Host:      "localhost",
		ShortMsg:  "short blabla",
		FullMsg:   "lllllllllllllllllllll",
		Timestamp: float64(time.Now().UnixNano() / int64(time.Second)),
		Level:     1,
		Facility:  "graylogd test",
	}
	b, err := json.Marshal(realLog)
	ast.Nil(err)

	client.Log(string(b))
	<-waitChan
}
