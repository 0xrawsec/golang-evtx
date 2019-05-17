package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

var (
	// system.evtx
	oneChunckEvtx     = "one-chunk.evtx"
	evtxFile          = "system.evtx"
	forwardedEvtxFile = "forwarded-events.evtx"
	// Sysmon
	sysmonFile = "sysmon.evtx"
	// AppReadyness
	appReadyFile = "files/Microsoft-Windows-AppReadiness%4Operational.evtx"
	// NTFS Operational
	ntfsOperational  = "files/Microsoft-Windows-Ntfs%4Operational.evtx"
	testfilesDir     = "./files"
	sysmonEventCount = 50213 // computed externally with evtxexport
)

func init() {
	//log.InitLogger(log.LDebug)
}

func TestParseAt(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	offsetChunk := 0x033c1000
	offsetElt := 0x21c

	c, err := ef.FetchRawChunk(int64(offsetChunk))
	if err != nil && err != io.EOF {
		panic(err)
	}
	reader := bytes.NewReader(c.Data)
	evtx.GoToSeeker(reader, int64(offsetElt))
	elt, _ := evtx.Parse(reader, &c, false)
	switch elt.(type) {
	case *evtx.Fragment:
		t.Log(string(evtx.ToJSON(elt.(*evtx.Fragment).GoEvtxMap())))
	case *evtx.TemplateInstance:
		t.Log(string(evtx.ToJSON(elt.(*evtx.TemplateInstance).GoEvtxMap())))
	default:
		t.Log(elt)

	}
}

func TestNodeTree(t *testing.T) {
	ef, _ := evtx.Open(evtxFile)
	offsetChunk := 0x00251000
	offsetElt := 1852

	c, err := ef.FetchRawChunk(int64(offsetChunk))
	reader := bytes.NewReader(c.Data)
	evtx.GoToSeeker(reader, int64(offsetElt))
	elt, err := evtx.Parse(reader, &c, false)
	if err != nil {
		log.Debug(elt)
		panic(err)
	}

	temp := elt.(*evtx.TemplateInstance)
	//Debug
	l := make([]string, len(temp.Definition.Data.Elements))
	for _, e := range temp.Definition.Data.Elements {
		switch e.(type) {
		case *evtx.ElementStart:
			l = append(l, fmt.Sprintf("%T", e))
			t.Log(e.(*evtx.ElementStart).Name.String())
		case *evtx.OptionalSubstitution:
			l = append(l, fmt.Sprintf("%T", temp.Data.Values[e.(*evtx.OptionalSubstitution).SubID]))
		default:
			l = append(l, fmt.Sprintf("%T", e))
		}
	}
	t.Log(l)
	// Debug
	gem := temp.GoEvtxMap()
	t.Log(string(evtx.ToJSON(gem)))
	if err != nil {
		t.Error(err)
	}
	t.Log(string(evtx.ToJSON(gem)))
}

func TestParseOneChunk(t *testing.T) {
	ef, _ := evtx.Open(forwardedEvtxFile)
	offsetChunk := int64(0x016e1000)
	c, err := ef.FetchChunk(offsetChunk)
	if err != nil && err != io.EOF {
		panic(err)
	}
	for _, eo := range c.EventOffsets {
		e := c.ParseEvent(int64(eo))
		gem, _ := e.GoEvtxMap(&c)
		t.Log(string(evtx.ToJSON(gem)))
	}
}

func TestParseEventAt(t *testing.T) {
	ef, _ := evtx.Open(forwardedEvtxFile)
	offsetChunk := 0x016e1000
	offsetEvent := 0x016ef748 - offsetChunk
	c, err := ef.FetchChunk(int64(offsetChunk))
	if err != nil && err != io.EOF {
		panic(err)
	}
	e := c.ParseEvent(int64(offsetEvent))
	gem, err := e.GoEvtxMap(&c)
	if err != nil {
		panic(err)
	}
	t.Log(string(evtx.ToJSON(gem)))
}

func TestParseEventByID(t *testing.T) {
	filepath := appReadyFile
	t.Logf("Parsing: %s ", filepath)
	ef, _ := evtx.Open(filepath)
	eventRecordID := int64(1448)
loop:
	for c := range ef.Chunks() {
		for _, eo := range c.EventOffsets {
			e := c.ParseEvent(int64(eo))
			if e.Header.ID == eventRecordID {
				t.Logf("Offset Chunk: 0x%08x", c.Offset)
				t.Logf("Offset Event: 0x%08x", eo)
				gem, _ := e.GoEvtxMap(&c)
				t.Log(string(evtx.ToJSON(gem)))
				break loop
			}
		}
	}
}

func TestParseAllEvents(t *testing.T) {
	maxChunks := 1000
	chunkCount := 0
	ef, _ := evtx.Open(forwardedEvtxFile)
	log.Info(ef.Header)
	for c := range ef.Chunks() {
		//log.Info(c.Header)
		if chunkCount >= maxChunks && maxChunks >= 0 {
			break
		}
		for e := range c.Events() {
			t.Log(string(evtx.ToJSON(e)))
		}
		chunkCount++
	}
}

func TestParseChunk(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short test")
	}
	ef, _ := evtx.Open(sysmonFile)
	for e := range ef.FastEvents() {
		t.Log(string(evtx.ToJSON(e)))
	}
}

/*func TestMonitorChunks(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	stop := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * 10)
		stop <- true
	}()
	for c := range ef.MonitorChunks(stop, evtx.DefaultMonitorSleep) {
		t.Log(c.String())
	}
}*/

func TestRightOrderSlowEvents(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	i := 0
	prevErid := uint64(0)
	sPath := evtx.Path("/Event/System/EventRecordID/Value")
	for e := range ef.Events() {
		erid := e.GetUintStrict(&sPath)
		if erid < prevErid {
			t.Fatalf("Order is not guaranteed")
		}
		prevErid = erid
		i++
	}
	if sysmonEventCount != i {
		t.Fatalf("Bad event count %d instead of %d", i, sysmonEventCount)
	}
	t.Logf("Order is guaranteed accross events, %d events parsed", i)
}

func TestRightOrderFastEvents(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	prevErid := int64(0)
	i := 0
	for e := range ef.FastEvents() {
		erid := e.EventRecordID()
		if erid < prevErid {
			t.Fatalf("Order is not guaranteed")
		}
		prevErid = erid
		i++
	}
	if sysmonEventCount != i {
		t.Fatalf("Bad event count %d instead of %d", i, sysmonEventCount)
	}
	t.Logf("Order is guaranteed accross events, %d events parsed", i)
}

func TestFilter(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	p := evtx.Path("/Event/EventData/Data1/Value")
	for e := range ef.FastEvents() {
		if e.Equal(&p, "B2796A13-E43D-5880-0000-0010C55A0F00") {
			t.Log(string(evtx.ToJSON(e)))
			break
		}
	}
}

func TestEventIDFilter(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	for e := range ef.FastEvents() {
		if e.IsEventID("1", "12") {
			t.Log(string(evtx.ToJSON(e)))
		}
	}
}

func TestPatternFilter(t *testing.T) {
	pattern := regexp.MustCompile("MD5=D81F3ABB789C1D4504203171467A5E4E")
	ef, _ := evtx.Open(sysmonFile)
	p := evtx.Path("/Event/EventData/Data11/Value")
	for e := range ef.FastEvents() {
		if e.RegexMatch(&p, pattern) {
			t.Log(string(evtx.ToJSON(e)))
			break
		}
	}
}

func TestMapFilter(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	p := evtx.Path("/Event/EventData/Data11/Name")
	for e := range ef.FastEvents() {
		m, err := e.GetMap(&p)
		if err == nil {
			t.Log(string(evtx.ToJSON(m)))
			break
		}
	}
}

func TestMapWhereFilter(t *testing.T) {
	ef, _ := evtx.Open(sysmonFile)
	p := evtx.Path("/Event/EventData/Data1/Name")
	for e := range ef.FastEvents() {
		m, err := e.GetMapWhere(&p, "SourceProcessGUID")
		if err == nil {
			t.Log(string(evtx.ToJSON(m)))
			break
		}
	}
}

func TestBetweenFilter(t *testing.T) {
	i := 0
	ef, _ := evtx.Open(sysmonFile)
	t1, err := time.Parse(time.RFC3339, "2017-01-19T17:07:20+01:00")
	if err != nil {
		panic(err)
	}
	t2, err := time.Parse(time.RFC3339, "2017-01-19T17:07:21+01:00")
	if err != nil {
		panic(err)
	}
	for e := range ef.FastEvents() {
		if e.Between(t1, t2) {
			t.Log(string(evtx.ToJSON(e)))
			i++
		}
	}
	t.Logf("%d events between %v and %v", i, t1, t2)
}

func TestAllFiles(t *testing.T) {
	files, err := ioutil.ReadDir(testfilesDir)
	if err != nil {
		panic(err)
	}
	for _, fi := range files {
		fullpath := filepath.Join(testfilesDir, fi.Name())
		t.Logf("Parsing : %s", fullpath)
		ef, _ := evtx.Open(fullpath)
		for _ = range ef.FastEvents() {
		}
	}
}

func TestUserID(t *testing.T) {
	files, err := ioutil.ReadDir(testfilesDir)
	if err != nil {
		panic(err)
	}
	for _, fi := range files {
		fullpath := filepath.Join(testfilesDir, fi.Name())
		ef, _ := evtx.Open(fullpath)
		for e := range ef.FastEvents() {
			if uid, ok := e.UserID(); ok {
				if uid == "" {
					t.Log(string(evtx.ToJSON(e)))
				}
				t.Log(uid)
			}
		}
	}

}
