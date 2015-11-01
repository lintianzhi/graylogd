
## graylog daemon in golang

graylogd is a implementation for serving messages in GELF(Graylog Extended Log Format) in golang

### Example:

```
package main

import (
    "fmt"
    "net"

    "github.com/lintianzhi/graylogd"
)

func main() {
    conf := graylogd.Config{
        ListenAddr: ":12201",
        // handle raw message
        //HandleRaw: func(b []byte) {
        //  fmt.Println(string(b))
        //  fmt.Println(len(b))
        //},
        HandleGELF: func(gelf *graylogd.GelfLog, addi map[string]interface{}) {
            fmt.Println(gelf)
            fmt.Println(addi)
        },
        HandleError: func(addr *net.UDPAddr, err error) {
            fmt.Println("err:", err)
        },
    }

    logd, _ := graylogd.NewGraylogd(conf)
    err := logd.Run()
    if err != nil {
        fmt.Println("run failed:", err)
        return
    }
    select {}
}
```
