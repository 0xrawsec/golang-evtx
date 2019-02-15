package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/0xrawsec/golang-evtx/evtx"
)

type TcpJSON struct {
	out *json.Encoder
	Tag string
}

func (tj *TcpJSON) Open(url string) error {
	conn, err := net.Dial("tcp", url)
	if err != nil {
		return errors.New(fmt.Sprintf("Can't connect to remote tcp log server: %s", url))
	}
	tj.out = json.NewEncoder(conn)
	return nil
}

func (tj *TcpJSON) Request(message *evtx.GoEvtxMap) {
	mark := evtx.GoEvtxMap{
		"tags": tj.Tag,
	}
	message.Add(mark)
	tj.out.Encode(message)
}
