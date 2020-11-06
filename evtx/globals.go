package evtx

import (
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"time"
)

/////////////////////////////////// Errors /////////////////////////////////////

var (
	ErrInvalidEvent = errors.New("Error Invalid Event")
	// ErrBadEvtxFile error definition
	ErrBadEvtxFile = errors.New("Bad file magic")
	// ErrBadChunkMagic error definition
	ErrBadChunkMagic = errors.New("Bad chunk magic")
	// ErrBadChunkSize error definition
	ErrBadChunkSize = errors.New("Bad chunk size")
	ErrTokenEOF     = errors.New("TokenEOF")
)

//////////////////////// Global Variables and their setters /////////////////////
var (
	// ModeCarving flag to identify we run in carving mode
	ModeCarving = false
	// DefaultMonitorSleep default sleep time between two file update checks when
	// monitoring file
	DefaultMonitorSleep = 250 * time.Millisecond
	// MaxJobs controls the maximum jobs for some functions (MonitorEvents ...)
	MaxJobs = int(math.Floor(float64(runtime.NumCPU()) / 2))
)

// SetModeCarving changes the carving mode to value
func SetModeCarving(value bool) {
	ModeCarving = value
}

// SetMonitorSleep sets the sleep time between two file update checks when
// monitoring file
func SetMonitorSleep(d time.Duration) {
	DefaultMonitorSleep = d
}

func SetMaxJobs(jobs int) {
	MaxJobs = jobs
}

////////////////////////// EVTX Constants and globs ////////////////////////////

const (
	EventHeaderSize = 24
	EvtxMagic       = "ElfFile"

	// ChunkSize 64KB
	ChunkSize = 0x10000
	// ChunkHeaderSize
	ChunkHeaderSize = 0x80
	// ChunkMagic magic string
	ChunkMagic         = "ElfChnk\x00"
	sizeStringBucket   = 0x40
	sizeTemplateBucket = 0x20
	DefaultNameOffset  = -1

	EventMagic = "\x2a\x2a\x00\x00"

	// MaxSliceSize is a constant used to control the allocation size of some
	// structures. It is particularly useful to control side effect when carving
	MaxSliceSize = ChunkSize
)

var (
	Endianness = binary.LittleEndian
	// Used for debug purposes
	lastParsedElements = &LastParsedElements{elements: [4]Element{}}
)

//////////////////////////////// BinXMLTokens //////////////////////////////////

const (
	TokenEOF                                             = 0x00
	TokenOpenStartElementTag1, TokenOpenStartElementTag2 = 0x01, 0x41 // (<)name>
	TokenCloseStartElementTag                            = 0x02       // <name(>)
	TokenCloseEmptyElementTag                            = 0x03       // <name(/>)
	TokenEndElementTag                                   = 0x04       // (</name>)
	TokenValue1, TokenValue2                             = 0x05, 0x45 // attribute = ‘‘(value)’’
	TokenAttribute1, TokenAttribute2                     = 0x06, 0x46 // (attribute) = ‘‘value’’
	TokenCDataSection1, TokenCDataSection2               = 0x07, 0x47
	TokenCharRef1, TokenCharRef2                         = 0x08, 0x48
	TokenEntityRef1, TokenEntityRef2                     = 0x09, 0x49
	TokenPITarget                                        = 0x0a
	TokenPIData                                          = 0x0b
	TokenTemplateInstance                                = 0x0c
	TokenNormalSubstitution                              = 0x0d
	TokenOptionalSubstitution                            = 0x0e
	FragmentHeaderToken                                  = 0x0f
)

//////////////////////////////// BinXMLValues //////////////////////////////////

const (
	NullType       = 0x00
	StringType     = 0x01
	AnsiStringType = 0x02
	Int8Type       = 0x03
	UInt8Type      = 0x04
	Int16Type      = 0x05
	UInt16Type     = 0x06
	Int32Type      = 0x07
	UInt32Type     = 0x08
	Int64Type      = 0x09
	UInt64Type     = 0x0a
	Real32Type     = 0x0b
	Real64Type     = 0x0c
	BoolType       = 0x0d
	BinaryType     = 0x0e
	GuidType       = 0x0f
	SizeTType      = 0x10
	FileTimeType   = 0x11
	SysTimeType    = 0x12
	SidType        = 0x13
	HexInt32Type   = 0x14
	HexInt64Type   = 0x15
	EvtHandle      = 0x20
	BinXmlType     = 0x21
	EvtXml         = 0x23

	// If the MSB of the value type (0x80) is use to indicate an array type
	ArrayType = 0x80
)

/////////////////////////////////// GoEvtx /////////////////////////////////////

var (
	// Paths used by GoEvtxMap
	PathSeparator     = "/"
	XmlnsPath         = Path("/Event/xmlns")
	ChannelPath       = Path("/Event/System/Channel")
	EventIDPath       = Path("/Event/System/EventID")
	EventIDPath2      = Path("/Event/System/EventID/Value")
	EventRecordIDPath = Path("/Event/System/EventRecordID")
	SystemTimePath    = Path("/Event/System/TimeCreated/SystemTime")
	UserIDPath        = Path("/Event/System/Security/UserID")
)
