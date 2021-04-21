package output

import (
	"context"
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/olivere/elastic/v7"
	"time"
)

type Elastic struct {
	EsClient  *elastic.Client
	IndexName string
	EsUrl     string
}

func (e *Elastic) Open(url string) (err error) {
	e.EsClient, err = elastic.NewClient(
		elastic.SetURL(e.EsUrl), //
		elastic.SetSniff(false),
		elastic.SetHealthcheckInterval(10*time.Second),
		elastic.SetGzip(true),
	)
	return err
}

func (e *Elastic) Request(message *evtx.GoEvtxMap) {
	put1, err := e.EsClient.Index().
		Index(e.IndexName).
		BodyJson(string(evtx.ToJSON(message))).
		Do(context.Background())
	if err != nil {
		log.Errorf("Can 't connect to remote elastic log server: %s", e.EsUrl)
		return
	}
	log.Info(fmt.Sprintf("Indexed user %s to index %s, type %s\n", put1.Id, put1.Index, put1.Type))
	return
}
