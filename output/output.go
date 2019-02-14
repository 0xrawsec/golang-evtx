package output

import "github.com/0xrawsec/golang-evtx/evtx"

type Output interface {
	Open(url string) error
	Request(message *evtx.GoEvtxMap)
}
