/*
EVTX dumping utility, it can be used to carve raw data and recover EVTX events

Copyright (C) 2017  RawSec SARL (0xrawsec)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-evtx/output"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	// ExitSuccess RC
	ExitSuccess = 0
	// ExitFail RC
	ExitFail  = 1
	Version   = "Evtxdump 1.1"
	Copyright = "Evtxdump Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	License   = `License GPLv3: This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain
conditions;`
)

var (
	debug         bool
	carve         bool
	timestamp     bool
	version       bool
	unordered     bool
	statflag      bool
	offset        int64
	limit         int
	tag           string
	outTcp        string
	outHttp       string
	outType       string
	brURL         string
	cID           string
	topic         string
	start, stop   args.DateVar
	chunkHeaderRE = regexp.MustCompile(evtx.ChunkMagic)
	defaultTime   = time.Time{}
)

//////////////////////////// stat structure ////////////////////////////////////

type eventIDStat map[int64]uint

type stats struct {
	sync.RWMutex
	EventCount   uint
	ChannelStats map[string]eventIDStat
}

// stats contstructor
func newStats() stats {
	s := stats{}
	s.ChannelStats = make(map[string]eventIDStat)
	return s
}

// update stats in a stat sturcture
func (s *stats) update(channel string, eventID int64) {
	s.Lock()
	if _, ok := s.ChannelStats[channel]; !ok {
		s.ChannelStats[channel] = make(eventIDStat)
	}
	s.ChannelStats[channel][eventID]++
	s.EventCount++
	s.Unlock()
}

// prints in CSV format
func (s *stats) print() {
	fmt.Printf("Channel,EventID,Count\n")
	for c := range s.ChannelStats {
		for eid, cnt := range s.ChannelStats[c] {
			fmt.Printf("%s,%d,%d\n", c, eid, cnt)
		}
	}
	//fmt.Printf("Total Events: %d\n", s.EventCount)
}

/////////////////////////////// Carving functions //////////////////////////////

// Find the potential chunks
func findChunksOffsets(r io.ReadSeeker) (co chan int64) {
	co = make(chan int64, 42)
	realPrevOffset, _ := r.Seek(0, os.SEEK_CUR)
	go func() {
		defer close(co)
		rr := bufio.NewReader(r)
		for loc := chunkHeaderRE.FindReaderIndex(rr); loc != nil; loc = chunkHeaderRE.FindReaderIndex(rr) {
			realOffset, _ := r.Seek(0, os.SEEK_CUR)
			co <- realPrevOffset + int64(loc[0])
			realPrevOffset = realOffset - int64(rr.Buffered())
		}
	}()
	return
}

// return an evtx.Chunk object from a reader
func fetchChunkFromReader(r io.ReadSeeker, offset int64) (evtx.Chunk, error) {
	var err error
	c := evtx.NewChunk()
	evtx.GoToSeeker(r, offset)
	c.Offset = offset
	c.Data = make([]byte, evtx.ChunkSize)
	if _, err = r.Read(c.Data); err != nil {
		return c, err
	}
	reader := bytes.NewReader(c.Data)
	c.ParseChunkHeader(reader)
	if err = c.Header.Validate(); err != nil {
		return c, err
	}
	// Go to after Header
	evtx.GoToSeeker(reader, int64(c.Header.SizeHeader))
	c.ParseStringTable(reader)
	err = c.ParseTemplateTable(reader)
	if err != nil {
		return c, err
	}
	err = c.ParseEventOffsets(reader)
	if err != nil {
		return c, err
	}
	return c, nil
}

// main routine to carve a file
func carveFile(datafile string, offset int64, limit int) {
	chunkCnt := 0
	f, err := os.Open(datafile)
	if err != nil {
		log.LogErrorAndExit(err)
	}
	defer f.Close()
	f.Seek(offset, os.SEEK_SET)
	dup, err := os.Open(datafile)
	if err != nil {
		log.LogErrorAndExit(err)
	}
	defer dup.Close()
	dup.Seek(offset, os.SEEK_SET)

	for offset := range findChunksOffsets(f) {
		log.Infof("Parsing Chunk @ Offset: %d (0x%08[1]x)", offset)
		chunk, err := fetchChunkFromReader(dup, offset)
		if err != nil {
			log.LogError(err)
		}
		for e := range chunk.Events() {
			printEvent(e)
		}
		chunkCnt++

		if limit > 0 && chunkCnt >= limit {
			break
		}
		log.Debug("End of the loop")
	}
}

// small routine that prints the EVTX event
func printEvent(e *evtx.GoEvtxMap) {
	if e != nil {
		t, err := e.GetTime(&evtx.SystemTimePath)

		// If not between start and stop we do not print
		if time.Time(start) != defaultTime && time.Time(stop) != defaultTime {
			if t.Before(time.Time(start)) || t.After(time.Time(stop)) {
				return
			}
		}

		// If before start we do not print
		if time.Time(start) != defaultTime {
			if t.Before(time.Time(start)) {
				return
			}
		}

		// If after stop we do not print
		if time.Time(stop) != defaultTime {
			if t.After(time.Time(stop)) {
				return
			}
		}

		if timestamp {
			if err == nil {
				fmt.Printf("%d: %s\n", t.UnixNano(), string(evtx.ToJSON(e)))
			} else {
				log.Errorf("Event time not found: %s", string(evtx.ToJSON(e)))
			}
		} else {
			fmt.Printf("%s\n", string(evtx.ToJSON(e)))
		}

	}
}

///////////////////////////////// Main /////////////////////////////////////////

func main() {
	var memprofile, cpuprofile string
	flag.BoolVar(&debug, "d", debug, "Enable debug mode")
	flag.BoolVar(&carve, "c", carve, "Carve events from file")
	flag.BoolVar(&version, "V", version, "Show version and exit")
	flag.BoolVar(&timestamp, "t", timestamp, "Prints event timestamp (as int) at the beginning of line to make sorting easier")
	flag.BoolVar(&unordered, "u", unordered, "Does not care about ordering the events before printing (faster for large files)")
	flag.BoolVar(&statflag, "s", statflag, "Prints stats about events in files")
	flag.Int64Var(&offset, "o", offset, "Offset to start from (carving mode only)")
	flag.IntVar(&limit, "l", limit, "Limit the number of chunks to parse (carving mode only)")
	flag.Var(&start, "start", "Print logs starting from start")
	flag.Var(&stop, "stop", "Print logs before stop")

	flag.StringVar(&memprofile, "memprofile", "", "write memory profile to this file")
	flag.StringVar(&cpuprofile, "cpuprofile", "", "write cpu profile to this file")

	flag.StringVar(&outType, "type", "", "Type of remote log collector. JSON-over-HTTP, JSON-over-TCP, Kafka")
	flag.StringVar(&outHttp, "http", "", "url for sending output to remote site over HTTP")
	flag.StringVar(&outTcp, "tcp", "", "tcp socket address for sending output to remote site over TCP")
	flag.StringVar(&brURL, "brURL", "", "Kafka Broker URL")
	flag.StringVar(&topic, "topic", "", "Kafka topic")
	flag.StringVar(&cID, "cID", "", "Kafka client ID")
	flag.StringVar(&tag, "tag", "", "special tag for matching purpose on remote collector")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: %[1]s [OPTIONS] FILES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	// Debug mode
	if debug {
		log.InitLogger(log.LDebug)
	}

	// version
	if version {
		fmt.Fprintf(os.Stderr, "%s\n%s\n%s\n", Version, Copyright, License)
		return
	}

	// Handle profiling functions
	if memprofile != "" {
		defer func() {
			f, err := os.Create(memprofile)
			if err != nil {
				log.LogErrorAndExit(err)
			}
			pprof.WriteHeapProfile(f)
			f.Close()
		}()
	}

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.LogErrorAndExit(err)
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			log.LogErrorAndExit(err)
		}
		defer func() {
			pprof.StopCPUProfile()
			f.Close()
		}()
	}

	// init stats in case needed
	s := newStats()

	// init tcp sender if exists
	var out output.Output
	switch outType {
	case "http":
		httpOut := &output.HttpJSON{
			Url: outHttp,
			Tag: tag,
		}
		if err := httpOut.Open(outHttp); err != nil {
			log.Errorf("Can't init http conn", err)
		}
		out = httpOut
	case "tcp":
		tcpOut := &output.TcpJSON{
			Tag: tag,
		}
		if err := tcpOut.Open(outTcp); err != nil {
			log.Errorf("Can't init tcp conn", err)
		}
		out = tcpOut
	case "kafka":
		kafkaOut := &output.Kafka{
			BrokerURLs: brURL,
			Topic:      topic,
			ClientID:   cID,
			Tag:        tag,
		}
		if err := kafkaOut.Open(outHttp); err != nil {
			log.Errorf("Can't init Kafka conn", err)
		}
		out = kafkaOut
	}

	for _, evtxFile := range flag.Args() {
		switch {
		case carve:
		default:

		}
		if !carve {
			// Regular EVTX file
			ef, err := evtx.Open(evtxFile)
			if err != nil {
				log.Error(err)
				continue
			}
			for e := range ef.FastEvents() {
				if statflag {
					// We update the stats
					s.update(e.Channel(), e.EventID())
				} else {
					// We print events
					if outType != "" {
						out.Request(e)
					} else {
						printEvent(e)
					}
				}
			}
		} else {
			evtx.SetModeCarving(true)
			// We have to carve the file
			carveFile(evtxFile, offset, limit)
		}
	}

	// We print the stats if needed
	if statflag {
		s.print()
	}
}
