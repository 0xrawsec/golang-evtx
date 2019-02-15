package output

import (
	"bytes"
	"net/http"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

type HttpJSON struct {
	client *http.Client
	Url    string
	Tag    string
}

func (hj *HttpJSON) Open(url string) error {
	hj.client = &http.Client{}
	return nil
}

func (hj *HttpJSON) Request(message *evtx.GoEvtxMap) {
	mark := evtx.GoEvtxMap{
		"tags": hj.Tag,
	}
	message.Add(mark)
	req, err := http.NewRequest("POST", hj.Url, bytes.NewBuffer([]byte(evtx.ToJSON(message))))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hj.client.Do(req)
	if err != nil {
		log.Errorf("Can 't connect to remote http log server: %s", hj.Url)
	}
	defer resp.Body.Close()
}
