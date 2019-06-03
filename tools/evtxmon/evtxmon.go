/*
EVTX monitoring utility, it can be used to make statistics on event generation
and to dump events in real time to files.

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
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	// ExitSuccess RC
	ExitSuccess = 0
	// ExitFailure RC
	ExitFailure = 1
	Version     = "Evtxmon 1.1"
	Copyright   = "Evtxmon Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	License     = `License GPLv3: This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain
conditions;`
)

var (
	evtxfile        string
	version         bool
	statsFlag       bool
	debug           bool
	monitorExisting bool
	filters         args.ListIntVar
	duration        DurationArg
	output          string
	utctime         = evtx.Path("/Event/EventData/UtcTime")
)

type DurationArg time.Duration

func (da *DurationArg) String() string {
	return time.Duration(*da).String()
}

func (da *DurationArg) Set(input string) error {
	tda, err := time.ParseDuration(input)
	if err == nil {
		*da = DurationArg(tda)
	}
	return err
}

type Int64Slice []int64

func (is Int64Slice) Len() int {
	return len(is)
}

func (is Int64Slice) Swap(i, j int) {
	is[i], is[j] = is[j], is[i]
}
func (is Int64Slice) Less(i, j int) bool {
	return is[i] < is[j]
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

type Stats struct {
	sync.RWMutex
	Start         time.Time
	Stop          time.Time
	TimeLastEvent time.Time
	Filters       datastructs.SyncedSet
	EventCount    uint
	EventIDStats  map[int64]uint
	EventIDs      Int64Slice
}

func NewStats(filters ...int) (s Stats) {
	s.EventIDStats = make(map[int64]uint)
	s.EventIDs = make(Int64Slice, 0, 1024)
	s.Filters = datastructs.NewSyncedSet()
	for _, f := range filters {
		s.Filters.Add(int64(f))
	}
	return
}

func (s *Stats) InitStart() {
	s.Start = time.Now()
}

func (s *Stats) Update(e *evtx.GoEvtxMap) {
	s.Lock()
	defer s.Unlock()
	// We take only those not filtered
	if !s.Filters.Contains(e.EventID()) {
		s.TimeLastEvent = e.TimeCreated()
		s.EventCount++
		if _, ok := s.EventIDStats[e.EventID()]; !ok {
			s.EventIDs = append(s.EventIDs, e.EventID())
		}
		s.EventIDStats[e.EventID()]++
	}
}

func (s *Stats) DisplayStats() {
	s.RLock()
	defer s.RUnlock()
	fmt.Fprintf(os.Stderr, "Start: %s ", FormatTime(s.Start))
	fmt.Fprintf(os.Stderr, "TimeLastEvent: %s ", FormatTime(s.TimeLastEvent))
	fmt.Fprintf(os.Stderr, "EventCount: %d ", s.EventCount)
	eps := float64(s.EventCount) / time.Now().Sub(s.Start).Seconds()
	fmt.Fprintf(os.Stderr, "EPS: %.2f e/s\r", eps)
}

func (s *Stats) Summary() {
	s.RLock()
	defer s.RUnlock()
	s.Stop = time.Now()
	fmt.Printf("\n\n###### Summary #######\n\n")
	fmt.Printf("Start: %s\n", FormatTime(s.Start))
	fmt.Printf("Stop: %s\n", FormatTime(s.Stop))
	fmt.Printf("TimeLastEvent: %s\n", FormatTime(s.TimeLastEvent))
	fmt.Printf("Duration (stop - start): %s\n", s.Stop.Sub(s.Start))
	fmt.Printf("EventCount: %d\n", s.EventCount)
	eps := float64(s.EventCount) / s.Stop.Sub(s.Start).Seconds()
	fmt.Printf("Average EPS: %.2f eps\n", eps)
	fmt.Printf("EventIDs:\n")
	sort.Sort(s.EventIDs)
	for _, eid := range s.EventIDs {
		fmt.Printf("\t %d: %d (%.2f eps)\n", eid, s.EventIDStats[eid], float64(s.EventIDStats[eid])/s.Stop.Sub(s.Start).Seconds())
	}
}

func main() {
	var err error
	var ofile *os.File
	var writer *gzip.Writer

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] EVTX-FILE\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Var(&filters, "f", "Event ids to filter out")
	flag.Var(&duration, "t", "Timeout for the test")
	flag.BoolVar(&version, "V", version, "Show version information")
	flag.StringVar(&output, "w", output, "Write monitored events to output file")
	flag.BoolVar(&statsFlag, "s", statsFlag, "Outputs stats about events processed")
	flag.BoolVar(&debug, "d", debug, "Enable debug messages")
	flag.BoolVar(&monitorExisting, "e", monitorExisting, "Return also already existing events")

	flag.Parse()

	// set debug mode
	if debug {
		log.InitLogger(log.LDebug)
	}

	stats := NewStats(filters...)

	// Signal handler to catch interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		<-c
		// No error handling
		writer.Flush()
		writer.Close()
		ofile.Close()
		if statsFlag {
			stats.Summary()
		}
		os.Exit(ExitFailure)
	}()

	// version
	if version {
		fmt.Fprintf(os.Stderr, "%s\n%s\n%s\n", Version, Copyright, License)
		return
	}

	evtxfile = flag.Arg(0)
	if output != "" {
		ofile, err = os.Create(output)
		if err != nil {
			panic(err)
		}
		writer = gzip.NewWriter(ofile)

		defer writer.Flush()
		defer writer.Close()
		defer ofile.Close()
	}

	if evtxfile == "" {
		flag.Usage()
		os.Exit(1)
	} else {
		stop := make(chan bool, 1)
		ef, err := evtx.Open(evtxfile)
		if err != nil {
			log.LogErrorAndExit(err)
		}

		if statsFlag {
			go func() {
				for {
					time.Sleep(100 * time.Millisecond)
					stats.DisplayStats()
				}
			}()
		}

		if duration > 0 {
			go func() {
				start := time.Now()
				for time.Now().Sub(start) < time.Duration(duration) {
					time.Sleep(time.Millisecond * 500)
				}
				if statsFlag {
					stats.Summary()
					os.Exit(ExitFailure)
				}
			}()
		}

		stats.InitStart()
		if monitorExisting {
			ef.SetMonitorExisting(true)
		}
		for e := range ef.MonitorEvents(stop) {
			if output != "" {
				writer.Write(evtx.ToJSON(e))
				writer.Write([]byte("\n"))
				writer.Flush()
			}
			if statsFlag {
				stats.Update(e)
			} else {
				log.Infof("EventID:%d Time: %s EventRecordID: %d, ChunkCount: %d\n", e.EventID(), e.TimeCreated(), e.EventRecordID(), ef.Header.ChunkCount)
			}
		}
	}
}
