package evtx

import (
	"fmt"
	"io"
	"os"

	"github.com/0xrawsec/golang-utils/log"
)

////////////////////////////////// Helper //////////////////////////////////////

func checkParsingError(err error, reader io.ReadSeeker, e Element) {
	UpdateLastElements(e)
	if err != nil {
		log.DontPanicf("%s: parsing %T", err, e)
		DebugReader(reader, 10, 5)
	}
}

func checkFullParsingError(err error, reader io.ReadSeeker, e Element, c *Chunk) {
	UpdateLastElements(e)
	if err != nil {
		//log.DontPanicf("%s: parsing %T (chunk @ 0x%08x reader @ 0x%08x)", err, e, c.Offset, BackupSeeker(reader))
		if c != nil {
			log.DebugDontPanicf("%s: parsing %T (chunk @ 0x%08x reader @ 0x%08x)", err, e, c.Offset, BackupSeeker(reader))
		} else {
			log.DebugDontPanicf("%s: parsing %T (chunk @ NIL reader @ 0x%08x)", err, e, BackupSeeker(reader))
		}
		DebugReader(reader, 10, 5)
	}
}

///////////////////////////// ErrUnknownToken //////////////////////////////////

type ErrUnknownToken struct {
	Token uint8
}

func (e ErrUnknownToken) Error() string {
	return fmt.Sprintf("Unknown Token: 0x%02x", e.Token)
}

// Parse : parses an XMLElement from a reader object
// @reader : reader to parse the Element from
// @c : chunk pointer used for already parsed templates
// return (Element, error) : parsed XMLElement and error
func Parse(reader io.ReadSeeker, c *Chunk, tiFlag bool) (Element, error) {
	var token [1]byte
	var err error
	read, err := reader.Read(token[:])
	if read != 1 || err != nil {
		return EmptyElement{}, err
	}
	_, err = reader.Seek(-1, os.SEEK_CUR)
	if err != nil {
		return EmptyElement{}, err
	}
	switch token[0] {
	case FragmentHeaderToken:
		f := Fragment{}
		err = f.Parse(reader)
		checkFullParsingError(err, reader, &f, c)
		f.BinXMLElement, err = Parse(reader, c, tiFlag)
		checkFullParsingError(err, reader, &f, c)
		if err != nil {
			return &f, err
		}
		// We hack a bit over here creating a fake TemplateInstance to benefit from
		// the further GoEvtxMap convertion of it. Conceptually it makes sense since
		// we just create a template without substitutions.
		if _, ok := f.BinXMLElement.(*ElementStart); ok {
			var e Element
			var ti TemplateInstance
			ti.Definition.Data.Elements = make([]Element, 0)

			ti.Definition.Data.Elements = append(ti.Definition.Data.Elements, f.BinXMLElement.(*ElementStart))
			for e, err = Parse(reader, c, tiFlag); err == nil; e, err = Parse(reader, c, tiFlag) {
				ti.Definition.Data.Elements = append(ti.Definition.Data.Elements, e)
				if _, ok := e.(*BinXMLEOF); ok {
					break
				}
			}
			checkFullParsingError(err, reader, e, c)
			f.BinXMLElement = &ti
		}
		return &f, err
	case TokenOpenStartElementTag1, TokenOpenStartElementTag2:
		es := ElementStart{IsTemplateInstance: tiFlag}
		err = es.Parse(reader)
		checkFullParsingError(err, reader, &es, c)
		return &es, err
	case TokenNormalSubstitution:
		ns := NormalSubstitution{}
		err = ns.Parse(reader)
		checkParsingError(err, reader, &ns)
		return &ns, err
	case TokenOptionalSubstitution:
		os := OptionalSubstitution{}
		err = os.Parse(reader)
		checkParsingError(err, reader, &os)
		return &os, err
	case TokenCharRef1:
		tcr := CharEntityRef{}
		err = tcr.Parse(reader)
		checkParsingError(err, reader, &tcr)
		return &tcr, err
	case TokenTemplateInstance:
		var offset int32
		ti := TemplateInstance{}
		if c != nil {
			// Check if template already parsed
			offset, err = ti.DataOffset(reader)
			if err != nil {
				return nil, err
			}
			if t, ok := c.TemplateTable[offset]; ok {
				// We have now to fix the offset to continue to read
				err = ti.ParseTemplateDefinitionHeader(reader)
				if err != nil {
					return nil, err
				}
				// Only the definition is valid, not the data
				ti.Definition.Data = t
				// We jump over the template definition data if needed
				if int64(offset) == BackupSeeker(reader) {
					// We patch offset to jump off to arrive after definition data size
					RelGoToSeeker(reader, int64(ti.Definition.Data.Size)+24)
				}
				// We parse the data
				err = ti.Data.Parse(reader)
				if err != nil {
					return nil, err
				}
				return &ti, nil
			}
		}
		// We have to parse the template since it cannot be found the template table
		err = ti.Parse(reader)
		if c != nil {
			// Update template table
			c.TemplateTable[ti.Definition.Header.DataOffset] = ti.Definition.Data
		}
		checkParsingError(err, reader, &ti)
		return &ti, err
	case TokenValue1, TokenValue2:
		// ValueText
		vt := ValueText{}
		err = vt.Parse(reader)
		checkParsingError(err, reader, &vt)
		return &vt, err

	case TokenEntityRef1, TokenEntityRef2:
		e := BinXMLEntityReference{}
		err = e.Parse(reader)
		checkParsingError(err, reader, &e)
		return &e, err

	case TokenEndElementTag:
		b := BinXMLEndElementTag{}
		err = b.Parse(reader)
		checkParsingError(err, reader, &b)
		return &b, err
	case TokenCloseStartElementTag:
		t := BinXMLCloseStartElementTag{}
		err = t.Parse(reader)
		checkParsingError(err, reader, &t)
		return &t, err
	case TokenCloseEmptyElementTag:
		t := BinXMLCloseEmptyElementTag{}
		err = t.Parse(reader)
		checkParsingError(err, reader, &t)
		return &t, err
	case TokenEOF:
		b := BinXMLEOF{}
		err = b.Parse(reader)
		checkParsingError(err, reader, &b)
		return &b, nil
	}
	//log.DontPanic(ErrUnknownToken{token[0]})
	log.DebugDontPanic(ErrUnknownToken{token[0]})
	return EmptyElement{}, ErrUnknownToken{token[0]}
}

// ParseValueReader : Parse a value from a reader according to a ValueDescriptor
// @vd : a ValueDescriptor structure
// @reader : the reader position at the offset of the value that have to be parsed
// return (Element, error) : a XMLElement and error
func ParseValueReader(vd ValueDescriptor, reader io.ReadSeeker) (Element, error) {
	var err error
	t := vd.ValType
	switch {
	case t.IsType(NullType):
		n := ValueNull{Size: vd.Size}
		n.Parse(reader)
		return &n, err
	case t.IsType(StringType):
		str := ValueString{Size: vd.Size}
		err = str.Parse(reader)
		return &str, err
	case t.IsType(AnsiStringType):
		astring := AnsiString{Size: vd.Size}
		err = astring.Parse(reader)
		return &astring, err
	case t.IsType(Int8Type):
		i := ValueInt8{}
		err = i.Parse(reader)
		return &i, err
	case t.IsType(UInt8Type):
		u := ValueUInt8{}
		err = u.Parse(reader)
		return &u, err
	case t.IsType(Int16Type):
		i := ValueInt16{}
		err = i.Parse(reader)
		return &i, err
	case t.IsType(UInt16Type):
		u := ValueUInt16{}
		err = u.Parse(reader)
		return &u, err
	case t.IsType(Int32Type):
		i := ValueInt32{}
		err = i.Parse(reader)
		return &i, err
	case t.IsType(UInt32Type):
		u := ValueUInt32{}
		err = u.Parse(reader)
		return &u, err
	case t.IsType(Int64Type):
		i := ValueInt64{}
		err = i.Parse(reader)
		return &i, err
	case t.IsType(UInt64Type):
		u := ValueUInt64{}
		err = u.Parse(reader)
		return &u, err
		//Real32Type is missing
		//Real64Type is missing
	case t.IsType(Real64Type):
		r := ValueReal64{}
		err = r.Parse(reader)
		return &r, err
	case t.IsType(BoolType):
		b := ValueBool{}
		err = b.Parse(reader)
		return &b, err
	case t.IsType(BinaryType):
		binary := ValueBinary{Size: vd.Size}
		err = binary.Parse(reader)
		return &binary, err
	case t.IsType(GuidType):
		var guid ValueGUID
		err = guid.Parse(reader)
		return &guid, err
		//SizeTType is missing
	case t.IsType(FileTimeType):
		filetime := ValueFileTime{}
		err = filetime.Parse(reader)
		return &filetime, err
	case t.IsType(SysTimeType):
		systime := ValueSysTime{}
		err = systime.Parse(reader)
		return &systime, err
	case t.IsType(SidType):
		var sid ValueSID
		err = sid.Parse(reader)
		return &sid, err
	case t.IsType(HexInt32Type):
		hi := ValueHexInt32{}
		err = hi.Parse(reader)
		return &hi, err
	case t.IsType(HexInt64Type):
		hi := ValueHexInt64{}
		err = hi.Parse(reader)
		return &hi, err
		//EvtHandle type is missing but unknown
	case t.IsType(BinXmlType):
		var elt Element
		// Must be a Fragment
		//elt, err := Parse(reader, c)
		elt, err = Parse(reader, nil, true)
		if err != nil {
			//panic(err)
			log.LogError(err)
			log.DebugDontPanic(err)
		}
		return elt, err
		//EvtXML type is missing but unknown
	case t.IsArrayOf(StringType):
		st := ValueStringTable{Size: vd.Size}
		err = st.Parse(reader)
		return &st, err
		// Many Array Types are missing
	case t.IsArrayOf(UInt16Type):
		a := ValueArrayUInt16{Size: vd.Size}
		err = a.Parse(reader)
		return &a, err
	case t.IsArrayOf(UInt64Type):
		a := ValueArrayUInt64{Size: vd.Size}
		err = a.Parse(reader)
		return &a, err
	default:
		// TODO: May cause crap
		uv := UnkVal{BackupSeeker(reader), t, vd}
		// Jump over the value data if we don't know it
		_, err = reader.Seek(int64(vd.Size), os.SEEK_CUR)
		if err != nil {
			panic(err)
		}
		return &uv, nil
	}
}
