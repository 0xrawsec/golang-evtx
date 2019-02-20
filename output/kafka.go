package output

import (
	"context"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/snappy"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

type Kafka struct {
	conn       *kafka.Writer
	BrokerURLs string
	ClientID   string
	Topic      string
	Tag        string
}

func (k *Kafka) Open(url string) error {
	dialer := &kafka.Dialer{
		Timeout:  10 * time.Second,
		ClientID: k.ClientID,
	}

	config := kafka.WriterConfig{
		Brokers:          []string{k.BrokerURLs},
		Topic:            k.Topic,
		Balancer:         &kafka.LeastBytes{},
		Dialer:           dialer,
		WriteTimeout:     10 * time.Second,
		ReadTimeout:      10 * time.Second,
		CompressionCodec: snappy.NewCompressionCodec(),
	}
	k.conn = kafka.NewWriter(config)
	return nil
}

func (k *Kafka) Request(message *evtx.GoEvtxMap) {
	mark := evtx.GoEvtxMap{
		"tags": k.Tag,
	}
	message.Add(mark)
	body := kafka.Message{
		Key:   nil,
		Value: evtx.ToJSON(message),
		Time:  time.Now(),
	}
	err := k.conn.WriteMessages(context.Background(), body)
	if err != nil {
		log.Error(err)
	}
}
