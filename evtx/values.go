package evtx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/0xrawsec/golang-utils/encoding"
)

type Value interface {
	// Repr is the way it is represented in GoEvtx
	Repr() interface{}
	Value() interface{}
	String() string
}

type ValueType uint8

////////////////////////////////// Utilities ///////////////////////////////////

func (v *ValueType) IsType(tvt ValueType) bool {
	return *v == tvt
}

func (v *ValueType) IsArray() bool {
	return (*v)&ArrayType == ArrayType
}

func (v *ValueType) IsArrayOf(tvt ValueType) bool {
	return v.IsArray() && ((*v)&tvt == tvt)
}

////////////////////////////////// NullType ////////////////////////////////////

type UnkVal struct {
	Offset int64
	Token  ValueType
	Desc   ValueDescriptor
}

func (*UnkVal) Parse(reader io.ReadSeeker) error {
	return nil
}

func (u *UnkVal) String() string {
	return fmt.Sprintf("Unknown value: %s @ 0x%08x", u.Desc, u.Offset)
}

func (u *UnkVal) Repr() interface{} {
	return u.String()
}

func (u *UnkVal) Value() interface{} {
	return u.Token
}

////////////////////////////////// NullType ////////////////////////////////////

type ValueNull struct {
	Size int16
}

func (n *ValueNull) Parse(reader io.ReadSeeker) error {
	_, err := reader.Seek(int64(n.Size), os.SEEK_CUR)
	return err
}

func (ValueNull) String() string {
	return ""
}

func (ValueNull) Value() interface{} {
	return nil
}

func (ValueNull) Repr() interface{} {
	return "NULL"
}

////////////////////////////////// Int8 ///////////////////////////////////////

type ValueInt8 struct {
	value int8
}

func (i *ValueInt8) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &i.value, Endianness)
}

func (i *ValueInt8) String() string {
	return fmt.Sprintf("%d", i.value)
}

func (i *ValueInt8) Value() interface{} {
	return i.value
}

func (i *ValueInt8) Repr() interface{} {
	return i.String()
}

////////////////////////////////// UInt8 ///////////////////////////////////////

type ValueUInt8 struct {
	value uint8
}

func (u *ValueUInt8) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &u.value, Endianness)
}

func (u *ValueUInt8) String() string {
	return fmt.Sprintf("%d", u.value)
}

func (u *ValueUInt8) Value() interface{} {
	return u.value
}

func (u *ValueUInt8) Repr() interface{} {
	return u.String()
}

////////////////////////////////// Int16 ///////////////////////////////////////

type ValueInt16 struct {
	value int16
}

func (i *ValueInt16) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &i.value, Endianness)
}

func (i *ValueInt16) String() string {
	return fmt.Sprintf("%d", i.value)
}

func (i *ValueInt16) Value() interface{} {
	return i.value
}

func (i *ValueInt16) Repr() interface{} {
	return i.String()
}

////////////////////////////////// UInt16 //////////////////////////////////////

type ValueUInt16 struct {
	value uint16
}

func (u *ValueUInt16) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &u.value, Endianness)
}

func (u *ValueUInt16) String() string {
	return fmt.Sprintf("%d", u.value)
}

func (u *ValueUInt16) Value() interface{} {
	return u.value
}

func (u *ValueUInt16) Repr() interface{} {
	return u.String()
}

////////////////////////////////// Int32 //////////////////////////////////////

type ValueInt32 struct {
	value int32
}

func (i *ValueInt32) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &i.value, Endianness)
}

func (i *ValueInt32) String() string {
	return fmt.Sprintf("%d", i.value)
}

func (i *ValueInt32) Value() interface{} {
	return i.value
}

func (i *ValueInt32) Repr() interface{} {
	return i.String()
}

////////////////////////////////// UInt32 //////////////////////////////////////
////////////////////////////////// ValueHexInt32 ///////////////////////////////

type ValueUInt32 struct {
	value uint32
}

type ValueHexInt32 struct {
	ValueUInt32
}

func (u *ValueUInt32) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &u.value, Endianness)
}

func (u *ValueUInt32) String() string {
	return fmt.Sprintf("%d", u.value)
}

func (u *ValueUInt32) Value() interface{} {
	return u.value
}

func (u *ValueUInt32) Repr() interface{} {
	return u.String()
}

func (i *ValueHexInt32) String() string {
	return fmt.Sprintf("0x%04x", i.value)
}

func (i *ValueHexInt32) Value() interface{} {
	return i.Value()
}

func (i *ValueHexInt32) Repr() interface{} {
	return i.String()
}

////////////////////////////////// Int32 //////////////////////////////////////

type ValueInt64 struct {
	value int64
}

func (i *ValueInt64) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &i.value, Endianness)
}

func (i *ValueInt64) String() string {
	return fmt.Sprintf("%d", i.value)
}

func (i *ValueInt64) Value() interface{} {
	return i.value
}

func (i *ValueInt64) Repr() interface{} {
	return i.String()
}

////////////////////////////////// UInt64 //////////////////////////////////////
///////////////////////////////// HexInt64Type /////////////////////////////////

type ValueUInt64 struct {
	value uint64
}

// Just for display so that we have not the unsigned format of fmt
type ValueHexInt64 struct {
	ValueUInt64
}

func (u *ValueUInt64) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &u.value, Endianness)
}

func (u *ValueUInt64) String() string {
	return fmt.Sprintf("%d", u.value)
}

func (u *ValueUInt64) Value() interface{} {
	return u.value
}

func (u *ValueUInt64) Repr() interface{} {
	return u.String()
}

func (i *ValueHexInt64) String() string {
	return fmt.Sprintf("0x%08x", i.value)
}

func (i *ValueHexInt64) Value() interface{} {
	return i.Value()
}

func (i *ValueHexInt64) Repr() interface{} {
	return i.String()
}

///////////////////////////////// Real32Type //////////////////////////////////
/// Experimental

type ValueReal32 struct {
	value float32
}

func (v *ValueReal32) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &v.value, Endianness)
}

func (v *ValueReal32) String() string {
	return fmt.Sprintf("%f", v.value)
}

func (v *ValueReal32) Value() interface{} {
	return v.value
}

func (v *ValueReal32) Repr() interface{} {
	return v.String()
}

///////////////////////////////// Real64Type //////////////////////////////////

type ValueReal64 struct {
	value float64
}

func (v *ValueReal64) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &v.value, Endianness)
}

func (v *ValueReal64) String() string {
	return fmt.Sprintf("%f", v.value)
}

func (v *ValueReal64) Value() interface{} {
	return v.value
}

func (v *ValueReal64) Repr() interface{} {
	return v.String()
}

///////////////////////////////// UTF16String //////////////////////////////////

type ValueString struct {
	Size  int16
	value UTF16String
}

func (s *ValueString) Parse(reader io.ReadSeeker) error {
	//len := ReadSeekerSize(reader)
	/*if len%2 != 0 {
		return fmt.Errorf("Bad string size")
	}*/
	if s.Size > 0 {
		s.value = make(UTF16String, s.Size/2)
		return encoding.UnmarshaInitSlice(reader, &s.value, Endianness)
	}
	return nil
}

func (s *ValueString) String() string {
	return string(s.value.ToASCII())
}

func (s *ValueString) Value() interface{} {
	return s.value
}

func (s *ValueString) Repr() interface{} {
	return s.String()
}

///////////////////////////// UTF16StringArray /////////////////////////////////

type ValueStringTable struct {
	Size  int16
	value []UTF16String
}

func (st *ValueStringTable) Parse(reader io.ReadSeeker) error {
	cp := UTF16{}
	st.value = make([]UTF16String, 0)
	s := make(UTF16String, 0)
	for i := 0; i < int(st.Size/2); i++ {
		err := encoding.Unmarshal(reader, &cp, Endianness)
		if err != nil {
			panic(err)
		}
		if cp == UTF16EndOfString {
			if len(s) > 0 {
				st.value = append(st.value, s)
				s = make(UTF16String, 0)
			}
			continue
		}
		s = append(s, cp)
	}
	return nil
}

func (st *ValueStringTable) Bytes() []byte {
	w := new(bytes.Buffer)
	w.Write([]byte("["))
	for i, elt := range st.value {
		if elt.Len() == 0 {
			continue
		}
		w.Write([]byte(`"`))
		w.Write([]byte(elt.ToASCII()))
		w.Write([]byte(`"`))
		// Last element is always empty
		if i != len(st.value)-2 {
			w.Write([]byte(`, `))
		}
	}
	w.Write([]byte("]"))
	return w.Bytes()
}

func (st *ValueStringTable) String() string {
	return string(st.Bytes())
}

func (st *ValueStringTable) Value() interface{} {
	return st.value
}

func (st *ValueStringTable) Repr() interface{} {
	var out []string
	for _, elt := range st.value {
		if elt.Len() == 0 {
			continue
		}
		out = append(out, string(elt.ToASCII()))
	}
	return out
}

///////////////////////////// ValueArrayInt16 /////////////////////////////////

type ValueArrayUInt16 struct {
	Size  int16
	value []uint16
}

func (a *ValueArrayUInt16) Parse(reader io.ReadSeeker) error {
	if a.Size > 0 {
		if a.Size%2 == 0 {
			a.value = make([]uint16, int(a.Size/2))
			return encoding.UnmarshaInitSlice(reader, &a.value, Endianness)
		}
		return errors.New("Bad size data")
	}
	return nil
}

func (a *ValueArrayUInt16) String() string {
	return fmt.Sprintf("%v", a.value)
}

func (a *ValueArrayUInt16) Value() interface{} {
	return a.value
}

func (a *ValueArrayUInt16) Repr() interface{} {
	return a.value
}

///////////////////////////// ValueArrayUInt64 /////////////////////////////////

type ValueArrayUInt64 struct {
	Size  int16
	value []uint64
}

func (a *ValueArrayUInt64) Parse(reader io.ReadSeeker) error {
	if a.Size > 0 {
		if a.Size%8 == 0 {
			a.value = make([]uint64, int(a.Size/8))
			return encoding.UnmarshaInitSlice(reader, &a.value, Endianness)
		}
		return errors.New("Bad size data")
	}
	return nil
}

func (a *ValueArrayUInt64) String() string {
	return fmt.Sprintf("%v", a.value)
}

func (a *ValueArrayUInt64) Value() interface{} {
	return a.value
}

func (a *ValueArrayUInt64) Repr() interface{} {
	return a.value
}

////////////////////////////////// ANSIString //////////////////////////////////

type AnsiString struct {
	Size  int16
	value []byte
}

func (as *AnsiString) Parse(reader io.ReadSeeker) error {
	as.value = make([]byte, as.Size)
	return encoding.UnmarshaInitSlice(reader, &as.value, Endianness)
}

func (as *AnsiString) String() string {
	return string(as.value)
}

func (as *AnsiString) Value() interface{} {
	return as.value
}

func (as *AnsiString) Repr() interface{} {
	return as.value
}

/////////////////////////////////// SystemTime /////////////////////////////////

type SysTime struct {
	Year         int16
	Month        int16
	DayOfWeek    int16
	DayOfMonth   int16
	Hours        int16
	Minutes      int16
	Seconds      int16
	Milliseconds int16
}

func (s *SysTime) String() string {
	//"2015-12-10T17:56:53.515800800Z"
	return fmt.Sprintf("%d-%d-%dT%d:%d:%d.%dZ", s.Year, s.Month, s.DayOfMonth, s.Hours, s.Minutes, s.Seconds, s.Milliseconds)
}

type ValueSysTime struct {
	value SysTime
}

func (s *ValueSysTime) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &s.value, Endianness)
}

func (s *ValueSysTime) Time() UTCTime {
	return UTCTime(time.Date(int(s.value.Year),
		time.Month(s.value.Month),
		int(s.value.DayOfMonth),
		int(s.value.Hours),
		int(s.value.Minutes),
		int(s.value.Seconds),
		int(s.value.Milliseconds)*1000,
		time.UTC))
}

func (s *ValueSysTime) String() string {
	return s.value.String()
}

func (s *ValueSysTime) Value() interface{} {
	return s.value
}

func (s *ValueSysTime) Repr() interface{} {
	return s.Time()
}

/////////////////////////////////// ValueFileTime //////////////////////////////

type ValueFileTime struct {
	value FileTime
}

func (s *ValueFileTime) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &s.value, Endianness)
}

func (s *ValueFileTime) String() string {
	return s.value.String()
}

func (s *ValueFileTime) Value() interface{} {
	return s.value.Time()
}

func (s *ValueFileTime) Repr() interface{} {
	return s.value.Time()
}

///////////////////////////////// ValueBool //////////////////////////////////

type ValueBool struct {
	ValueInt32
}

func (b *ValueBool) Value() interface{} {
	return b.value == 0x1
}

func (b *ValueBool) String() string {
	return fmt.Sprintf("%t", b.Value())
}

func (b *ValueBool) Repr() interface{} {
	return fmt.Sprintf("%t", b.Value())
}

///////////////////////////////// ValueBinary //////////////////////////////////

type ValueBinary struct {
	Size  int16
	value []byte
}

func (b *ValueBinary) Parse(reader io.ReadSeeker) error {
	b.value = make([]byte, b.Size)
	if b.Size > 0 {
		return encoding.UnmarshaInitSlice(reader, &b.value, Endianness)
	}
	return nil
}

func (b *ValueBinary) String() string {
	return fmt.Sprintf("%*X", b.Size, b.value)
}

func (b *ValueBinary) Value() interface{} {
	return b.value
}

func (b *ValueBinary) Repr() interface{} {
	return b.String()
}

///////////////////////////////////// GUID /////////////////////////////////////

type GUID [16]byte

func (g *GUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13],
		g[14], g[15])
}

type ValueGUID struct {
	value GUID
}

func (g *ValueGUID) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &g.value, Endianness)
}

func (g *ValueGUID) String() string {
	return g.value.String()
}

func (g *ValueGUID) Value() interface{} {
	return g.value
}

func (g *ValueGUID) Repr() interface{} {
	return g.String()
}

///////////////////////////////////// SID /////////////////////////////////////
// Source: https://github.com/dutchcoders/evtxparser/blob/master/sid.go

type Sid struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority [6]uint8
	SubAuthority        []uint32
}

type ValueSID struct {
	value Sid
}

func (g *ValueSID) Parse(reader io.ReadSeeker) error {
	var err error
	err = encoding.Unmarshal(reader, &g.value.Revision, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &g.value.SubAuthorityCount, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &g.value.IdentifierAuthority, Endianness)
	if err != nil {
		return err
	}
	g.value.SubAuthority = make([]uint32, g.value.SubAuthorityCount)
	err = encoding.UnmarshaInitSlice(reader, &g.value.SubAuthority, Endianness)
	return err
}

func (g *ValueSID) String() string {
	s := fmt.Sprintf("S-%d", g.value.Revision)

	v := uint64(0)
	for _, ia := range g.value.IdentifierAuthority {
		v = v << 8
		v += uint64(ia)
	}
	s += fmt.Sprintf("-%d", v)

	for _, sa := range g.value.SubAuthority {
		s += fmt.Sprintf("-%d", sa)
	}
	return s
}

func (g *ValueSID) Value() interface{} {
	return g.value
}

func (g *ValueSID) Repr() interface{} {
	return g.String()
}
