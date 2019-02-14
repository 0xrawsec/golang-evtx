package output

import (
	"github.com/0xrawsec/golang-evtx/evtx"
	"net"
	"encoding/json"
	"errors"
	"fmt"
)

type TcpJSON struct {
	out *json.Encoder
}

func (tj *TcpJSON )Open (url string) error {
		conn, err := net.Dial("tcp", url)
		if err != nil {
			return errors.New(fmt.Sprintf("Can't connect to remote tcp log server: %s", url))
		}
		tj.out = json.NewEncoder(conn)
		return nil
}

func (tj *TcpJSON ) Request (message *evtx.GoEvtxMap)  {
	tj.out.Encode(message)
}
