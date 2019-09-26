package evtx

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/0xrawsec/golang-utils/log"
)

///////////////////////////// Utility Functions ////////////////////////////////

func ReadSeekerSize(reader io.ReadSeeker) int64 {
	old, err := reader.Seek(0, os.SEEK_CUR)
	if err != nil {
		panic(err)
	}
	len, err := reader.Seek(0, os.SEEK_END)
	if err != nil {
		panic(err)
	}
	_, err = reader.Seek(old, os.SEEK_SET)
	if err != nil {
		panic(err)
	}
	return len
}

func ToJSON(data interface{}) []byte {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return b
}

func DebugReader(reader io.ReadSeeker, before, after int64) {
	cur, err := reader.Seek(0, os.SEEK_CUR)
	if err != nil {
		panic(err)
	}
	if cur >= before {
		_, err = reader.Seek(-before, os.SEEK_CUR)
	} else {
		_, err = reader.Seek(0, os.SEEK_SET)
	}
	if err != nil {
		log.Debugf("before: %d, cur: %d", before, cur)
		panic(err)
	}
	b := make([]byte, before+after)
	reader.Read(b)
	var out string
	out += fmt.Sprintf("Relative offset: 0x%08x\n", cur)
	out += "Last parsed elements : "
	for _, e := range lastParsedElements {
		out += fmt.Sprintf("%T, ", e)
	}
	out += "\n"
	for i, c := range b {
		if int64(i) == before {
			out += fmt.Sprintf(">%02x< ", c)
		} else {
			out += fmt.Sprintf("%02x ", c)
		}
	}
	out += "\n"
	out += fmt.Sprintf("r2 helper: %x", b)
	log.Debug(out)
	_, err = reader.Seek(cur, os.SEEK_SET)
	if err != nil {
		panic(err)
	}
}

func UpdateLastElements(e Element) {
	copy(lastParsedElements[:], lastParsedElements[1:])
	lastParsedElements[len(lastParsedElements)-1] = e
}

func BackupSeeker(seeker io.Seeker) int64 {
	backup, err := seeker.Seek(0, os.SEEK_CUR)
	if err != nil {
		panic(err)
	}
	return backup
}

func GoToSeeker(seeker io.Seeker, offset int64) {
	_, err := seeker.Seek(offset, os.SEEK_SET)
	if err != nil {
		//panic(err)
	}
}

func RelGoToSeeker(seeker io.Seeker, offset int64) {
	_, err := seeker.Seek(offset, os.SEEK_CUR)
	if err != nil {
		//panic(err)
	}
}

//////////////////////////////// UTF16String ///////////////////////////////////
// NB: We keep those structure for compatibility with parts of the code
type UTF16 uint16

type UTF16String []uint16

var (
	UTF16EndOfString = uint16(0x0)
)

func (us *UTF16String) Len() int32 {
	return int32(len(*us)) * 2
}

func (us UTF16String) ToString() string {
	return strings.TrimRight(string(utf16.Decode([]uint16(us))), "\u0000")
}

/////////////////////////////////// UTCTime ///////////////////////////////////

// UTCTime structure definition
type UTCTime time.Time

// MarshalJSON implements JSON serialization
func (u UTCTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", time.Time(u).UTC().Format(time.RFC3339Nano))), nil
}

/////////////////////////////////// FileTime /////////////////////////////////

type FileTime struct {
	Nanoseconds int64
}

func (v *FileTime) Convert() (sec int64, nsec int64) {
	nano := int64(10000000)
	milli := int64(10000)
	sec = int64(float64(v.Nanoseconds-11644473600*nano) / float64(nano))
	nsec = (v.Nanoseconds - 11644473600*nano) - sec*milli
	return
}

func (s *FileTime) Time() UTCTime {
	sec, nsec := s.Convert()
	return UTCTime(time.Unix(sec, nsec))
}

func (s *FileTime) String() string {
	//"2015-12-10T17:56:53.515800800Z"
	sec, nsec := s.Convert()
	return time.Unix(sec, nsec).Format(time.RFC3339Nano)
}
