package evtx

import (
	"fmt"
	"io"

	"github.com/0xrawsec/golang-utils/encoding"
	"github.com/0xrawsec/golang-utils/log"
)

// EventIDType is an alias to the type of EventID
type EventIDType int64

//////////////////////////////// Interfaces Definition //////////////////////////

type Element interface {
	Parse(reader io.ReadSeeker) error
	//GetSize() int32
}

type AttributeData interface {
	/*
				Can be:
					value text
		      substitution
					character entity reference
					entity reference
	*/
	IsAttributeData() bool
	String() string
}

type Content interface {
	/*
		Can be:
		   an element
		   content string data
		   character entity reference
		   entity reference
		   CDATA section
		   PI
	*/
}

type ContentStringData interface {
	/*
		Can be:
		   value text
		   substitution
	*/
}

type Substitution interface {
	/*
		Can be:
		   normal substitution
		   optional substitution
	*/
}

type PI interface {
	/*
		Can be:
		   PI target
		   PI data
	*/

}

/////////////////////////////// BinXMLFrgamentHeader ///////////////////////////

// FragmentHeader : BinXMLFragmentHeader
type FragmentHeader struct {
	Token      int8
	MajVersion int8
	MinVersion int8
	Flags      int8
}

func (fh *FragmentHeader) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, fh, Endianness)
	if fh.Token != FragmentHeaderToken {
		return fmt.Errorf("Bad fragment header token (0x%02x) instead of 0x%02x", fh.Token, FragmentHeaderToken)
	}
	return err
}

func (fh FragmentHeader) String() string {
	return fmt.Sprintf("%T: %s", fh, string(ToJSON(fh)))
}

////////////////////////////////// BinXMLFragment //////////////////////////////

type Fragment struct {
	Offset        int64 // For debug
	Header        FragmentHeader
	BinXMLElement Element
}

func (f *Fragment) GoEvtxMap() *GoEvtxMap {
	switch f.BinXMLElement.(type) {
	case *TemplateInstance:
		pgem := f.BinXMLElement.(*TemplateInstance).GoEvtxMap()
		//pgem.SetEventRecordID(fmt.Sprintf("%d", f.EventID))
		//pgem.SetSystemTime(f.Timestamp)
		pgem.DelXmlns()
		return pgem
		/*case *ElementStart:
		elements := make([]Element, 0)
		elements = append(elements, f.BinXMLElement.(*ElementStart))
		for e, err := Parse(reader, nil); err == nil; e, err = Parse(reader, nil) {

		}*/
	}
	return nil
}

func (f *Fragment) Parse(reader io.ReadSeeker) error {
	f.Offset = BackupSeeker(reader)
	err := f.Header.Parse(reader)
	if err != nil {
		return err
	}
	return err
}

func (f Fragment) String() string {
	return fmt.Sprintf("%T: %s", f, string(ToJSON(f)))
}

/////////////////////////////// BinXMLElementStart /////////////////////////////

// ElementStart : BinXMLElementStart
type ElementStart struct {
	Offset             int64
	IsTemplateInstance bool
	Token              int8
	DepID              int16
	Size               int32
	NameOffset         int32 // relative to start of chunk
	Name               Name
	AttributeList      AttributeList
	EOESToken          uint8
}

func (es *ElementStart) Parse(reader io.ReadSeeker) (err error) {
	//var elt Element
	// Default value
	es.Offset = BackupSeeker(reader)
	es.NameOffset = DefaultNameOffset
	//currentOffset := BackupSeeker(reader)
	err = encoding.Unmarshal(reader, &es.Token, Endianness)
	if err != nil {
		return err
	}

	// If it is not part of a TemplateInstance there is not DepID
	// Source: https://msdn.microsoft.com/en-us/library/cc231354.aspx
	if es.IsTemplateInstance {
		err = encoding.Unmarshal(reader, &es.DepID, Endianness)
		if err != nil {
			return err
		}
	}

	err = encoding.Unmarshal(reader, &es.Size, Endianness)
	if err != nil {
		return err
	}

	err = encoding.Unmarshal(reader, &es.NameOffset, Endianness)
	if err != nil {
		return err
	}

	// The name maybe elsewhere (reason of NameOffset ???)
	backup := BackupSeeker(reader)
	if backup != int64(es.NameOffset) {
		GoToSeeker(reader, int64(es.NameOffset))
	}
	err = es.Name.Parse(reader)
	if err != nil {
		return err
	}
	// If the name is not following, we have to restore in order to parse the remaining
	if backup != int64(es.NameOffset) {
		GoToSeeker(reader, backup)
	}
	if es.Token == TokenOpenStartElementTag2 {
		err = es.AttributeList.Parse(reader)
		if err != nil {
			return err
		}
	}

	err = encoding.Unmarshal(reader, &es.EOESToken, Endianness)
	if err != nil {
		return err
	}

	if es.EOESToken != TokenCloseStartElementTag && es.EOESToken != TokenCloseEmptyElementTag {
		if es.Token == TokenOpenStartElementTag1 {
			//panic(fmt.Errorf("Bad close element token (0x%02x) instead of 0x%02x", es.EOESToken, TokenCloseEmptyElementTag))
			return fmt.Errorf("Bad close element token (0x%02x) instead of 0x%02x", es.EOESToken, TokenCloseEmptyElementTag)
		} else {
			//panic(fmt.Errorf("Bad close element token (0x%02x) instead of 0x%02x", es.EOESToken, TokenCloseStartElementTag))
			return fmt.Errorf("Bad close element token (0x%02x) instead of 0x%02x", es.EOESToken, TokenCloseStartElementTag)
		}
	}
	// Go back by one byte in order to generate the appropriate BinXMLElement in the chain of parsed elements
	RelGoToSeeker(reader, -1)
	return err
}

func (es *ElementStart) HasName() bool {
	return es.NameOffset != DefaultNameOffset
}

func (es ElementStart) String() string {
	return fmt.Sprintf("%T: %s", es, string(ToJSON(es)))
}

/////////////////////////// BinXMLNormalSubstitution ///////////////////////////
///////////////////////// BinXMLOptionalSubstitution ///////////////////////////

//NormalSubstitution : BinXmlNormalSubstitution
type NormalSubstitution struct {
	Token   int8
	SubID   int16
	ValType int8
}

type OptionalSubstitution struct {
	NormalSubstitution
}

func (n *NormalSubstitution) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &n.Token, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &n.SubID, Endianness)
	if err != nil {
		return err
	}
	return encoding.Unmarshal(reader, &n.ValType, Endianness)
}

func (n *NormalSubstitution) IsAttributeData() bool {
	return true
}

func (n *NormalSubstitution) String() string {
	return fmt.Sprintf("%T: %[1]v", *n)
}

///////////////////////////////// BinXMLAttribute //////////////////////////////

type Attribute struct {
	Token         int8
	NameOffset    int32 // relative to start of chunk
	Name          Name
	AttributeData Element
}

func (a *Attribute) IsLast() bool {
	return a.Token == TokenAttribute1
}

func (a *Attribute) Parse(reader io.ReadSeeker) error {
	var err error
	err = encoding.Unmarshal(reader, &a.Token, Endianness)
	if err != nil {
		return err
	}
	if a.Token != TokenAttribute1 && a.Token != TokenAttribute2 {
		return fmt.Errorf("Bad attribute Token : 0x%02x", uint8(a.Token))
	}
	err = encoding.Unmarshal(reader, &a.NameOffset, Endianness)
	if err != nil {
		return err
	}
	// It may happen that the name of the attribute is somewhere else but the data
	// is after the offset
	cursor := BackupSeeker(reader)
	if int64(a.NameOffset) != cursor {
		GoToSeeker(reader, int64(a.NameOffset))
	}
	a.Name.Parse(reader)
	if int64(a.NameOffset) != cursor {
		GoToSeeker(reader, cursor)
	}
	// TODO: may cause bug because of tiFlag
	a.AttributeData, err = Parse(reader, nil, false)
	return err
}

///////////////////////////// BinXMLAttributeList //////////////////////////////

type AttributeList struct {
	Size       int32
	Attributes []Attribute
}

func (al *AttributeList) ParseSize(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &al.Size, Endianness)
}

func (al *AttributeList) ParseAttributes(reader io.ReadSeeker) error {
	var err error
	al.Attributes = make([]Attribute, 0)
	// We stop when we reached the size of the attribute list
	for {
		attr := Attribute{}
		err = attr.Parse(reader)
		if err != nil {
			return err
		}
		al.Attributes = append(al.Attributes, attr)
		// Test if the attribute is the last one of the list
		if attr.IsLast() {
			break
		}
	}
	return err
}

func (al *AttributeList) Parse(reader io.ReadSeeker) error {
	err := al.ParseSize(reader)
	if err != nil {
		return err
	}
	return al.ParseAttributes(reader)
}

//////////////////////////////////// Name //////////////////////////////////////

// Name :
// same as ChunkString
type Name struct {
	OffsetPrevString int32
	Hash             uint16
	Size             uint16
	UTF16String      UTF16String
}

// Parse Element implementation
func (n *Name) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &n.OffsetPrevString, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &n.Hash, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &n.Size, Endianness)
	if err != nil {
		return err
	}

	// No need to control size since it is uint16
	n.UTF16String = make([]uint16, n.Size+1)

	err = encoding.UnmarshaInitSlice(reader, &n.UTF16String, Endianness)
	return err
}

func (n *Name) String() string {
	return n.UTF16String.ToString()
}

///////////////////////////// BinXmlEntityReference ////////////////////////////

type CharEntityRef struct {
	Token int8
	Value int16
}

func (cer *CharEntityRef) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, cer, Endianness)
	return err
}

///////////////////////////////// BinXmlValueText //////////////////////////////

type ValueText struct {
	Token   int8
	ValType int8
	Value   UnicodeTextString // UnicodeTextString
}

func (vt *ValueText) String() string {
	return vt.Value.String.ToString()
}

func (vt *ValueText) IsAttributeData() bool {
	return true
}

func (vt *ValueText) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &vt.Token, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &vt.ValType, Endianness)
	if err != nil {
		return err
	}
	if vt.ValType != StringType {
		return fmt.Errorf("Bad type, must be (0x%02x) StringType", StringType)
	}
	err = vt.Value.Parse(reader)
	return err
}

////////////////////////////// UnicodeTextString ///////////////////////////////

type UnicodeTextString struct {
	Size   int16       // Number of characters, has to be x2
	String UTF16String // UTF-16 little-endian string without an end-of-string character
}

func (uts *UnicodeTextString) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &uts.Size, Endianness)
	if err != nil {
		return err
	}

	if uts.Size > 0 {
		uts.String = make(UTF16String, uts.Size)
		err = encoding.UnmarshaInitSlice(reader, &uts.String, Endianness)
		//log.Debugf("len:%d value:%s", uts.Size, string(uts.String.ToASCII()))
	}

	return err
}

func (uts *UnicodeTextString) GetSize() int32 {
	return 2 + int32(uts.Size)*2
}

///////////////////////// Not Implemented Structures ///////////////////////////

// EntityReference : BinXmlEntityReference
type EntityReference struct {
	Token            int8
	EntityNameOffset int32
}

// CDATASection : BinXmlCDATASection
type CDATASection struct {
	Token int8
	Text  UnicodeTextString
}

// PITarget : BinXmlPITarget
type PITarget struct {
	Token      int8
	NameOffset int32 // relative to start of chunk
}

// PIData : BinXmlPIData
type PIData struct {
	Token int8
	Text  UnicodeTextString
}

////////////////////////// BinXmlTemplateInstance //////////////////////////////

func (ti *TemplateInstance) Root() Node {
	node, _ := NodeTree(ti.Definition.Data.Elements, 0)
	return node
}

func (ti *TemplateInstance) ElementToGoEvtx(elt Element) GoEvtxElement {
	switch elt.(type) {
	// BinXML specific
	case *ValueText:
		return elt.(*ValueText).String()
	case *OptionalSubstitution:
		s := elt.(*OptionalSubstitution)
		// Manage Carving mode
		switch {
		case int(s.SubID) < len(ti.Data.Values):
			return ti.ElementToGoEvtx(ti.Data.Values[int(s.SubID)])
		case !ModeCarving:
			panic("Index out of range")
		default:
			return nil
		}
	case *NormalSubstitution:
		s := elt.(*NormalSubstitution)
		// Manage Carving mode
		switch {
		case int(s.SubID) < len(ti.Data.Values):
			return ti.ElementToGoEvtx(ti.Data.Values[int(s.SubID)])
		case !ModeCarving:
			panic("Index out of range")
		default:
			return nil
		}
	case *Fragment:
		temp := elt.(*Fragment).BinXMLElement.(*TemplateInstance)
		root := temp.Root()
		return temp.NodeToGoEvtx(&root)
	case *TemplateInstance:
		temp := elt.(*TemplateInstance)
		root := temp.Root()
		return temp.NodeToGoEvtx(&root)
	case Value:
		if _, ok := elt.(Value).(*ValueNull); ok {
			// We return nil if is ValueNull
			return nil
		}
		return elt.(Value).Repr()
	case *BinXMLEntityReference:
		ers := elt.(*BinXMLEntityReference).String()
		if ers == "" {
			err := fmt.Errorf("Unknown entity reference: %s", ers)
			if !ModeCarving {
				panic(err)
			} else {
				log.LogError(err)
				return nil
			}
		}
		return ers

	default:
		err := fmt.Errorf("Don't know how to handle: %T", elt)
		if !ModeCarving {
			panic(err)
		} else {
			log.LogError(err)
			return nil
		}
	}
}

func (ti *TemplateInstance) NodeToGoEvtx(n *Node) GoEvtxMap {
	switch {
	case n.Start == nil && len(n.Child) == 1:
		m := make(GoEvtxMap)
		m[n.Child[0].Start.Name.String()] = ti.NodeToGoEvtx(n.Child[0])
		return m

	default:
		m := make(GoEvtxMap, len(n.Child))
		for i, c := range n.Child {
			node := ti.NodeToGoEvtx(c)
			switch {
			// It seems that on EVTX files forwarded to WECs we have sometime just a
			// Name attribute without value. We notice that this happened to Element
			// that can be NULL. Maybe it is a default assumption or it is due to an
			// upstream parsing bug unidentified yet. Anyway the easiest way is to
			// fix it here
			// Example:     "EventData": {
			//"Data": {
			//  "Name": "SourcePortName"
			//},
			//"Data16": {
			//  "Name": "DestinationPortName"
			//},
			// We only have one element Name
			case node.HasKeys("Name") && len(node) == 1:
				m[node["Name"].(string)] = ""
			// Case where the Node only has two elements Name and Value
			case node.HasKeys("Name", "Value") && len(node) == 2:
				m[node["Name"].(string)] = node["Value"]
			// All the other cases
			default:
				name := c.Start.Name.String()
				if _, ok := m[name]; ok {
					name = fmt.Sprintf("%s%d", name, i)
				}
				// If there is only one key "Value" we do not create a full node
				// Name: {"Value": blob} but Name: blob instead
				//if node.HasKeys("Value") && len(node) == 1 {
				if node.HasKeys("Value") && len(node) == 1 {
					m[name] = node["Value"]
				} else {
					// All the other cases
					m[name] = node
				}
			}
			// If we have only keys like "Name" "Value" top level is useless
			/*if node.HasKeys("Name", "Value") && len(node) == 2 {
			} else {
			}*/
		}

		// It is assumed that all the Elements have a string representation
		for _, e := range n.Element {
			ge := ti.ElementToGoEvtx(e)
			switch ge.(type) {
			case GoEvtxMap:
				other := ge.(GoEvtxMap)
				m.Add(other)
			case string:
				if ge != nil {
					if m["Value"] == nil {
						m["Value"] = ge.(string)
					} else {
						m["Value"] = m["Value"].(string) + ge.(string)
					}
				}
			default:
				m["Value"] = ti.ElementToGoEvtx(n.Element[0])
			}
		}
		// n.Start can be NULL in  carving mode
		if n.Start != nil {
			for _, attr := range n.Start.AttributeList.Attributes {
				gee := ti.ElementToGoEvtx(attr.AttributeData)
				// We have a ValueNull
				if gee != nil {
					m[attr.Name.String()] = gee
				}
			}
		}
		return m
	}
}

func (ti *TemplateInstance) GoEvtxMap() *GoEvtxMap {
	root := ti.Root()
	gem := ti.NodeToGoEvtx(&root)
	return &gem
}

// TemplateInstance : BinXmlTemplateInstance
type TemplateInstance struct {
	Token      int8
	Definition TemplateDefinition
	Data       TemplateInstanceData
}

func (ti *TemplateInstance) DataOffset(reader io.ReadSeeker) (offset int32, err error) {
	backup := BackupSeeker(reader)
	GoToSeeker(reader, backup+6)
	err = encoding.Unmarshal(reader, &offset, Endianness)
	GoToSeeker(reader, backup)
	return
}

func (ti *TemplateInstance) ParseTemplateDefinitionHeader(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &ti.Token, Endianness)
	if err != nil {
		return err
	}
	return ti.Definition.Header.Parse(reader)
}

func (ti *TemplateInstance) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &ti.Token, Endianness)
	if err != nil {
		return err
	}
	err = ti.Definition.Parse(reader)
	if err != nil {
		return err
	}
	err = ti.Data.Parse(reader)
	return err
}

func (ti TemplateInstance) String() string {
	/*root, _ := NodeTree(ti.Definition.Elements, 0)
	node := root
	for*/
	return fmt.Sprintf("%T: %s", ti, string(ToJSON(ti)))
}

////////////////////////// BinXmlTemplateDefinition //////////////////////////////

type TemplateDefinitionHeader struct {
	Unknown1   int8
	Unknown2   int32
	DataOffset int32
}

func (tdh *TemplateDefinitionHeader) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, tdh, Endianness)
}

type TemplateDefinitionData struct {
	Unknown3   int32
	ID         [16]byte
	Size       int32
	FragHeader FragmentHeader
	Elements   []Element
	EOFToken   int8
}

func (td *TemplateDefinitionData) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &td.Unknown3, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &td.ID, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &td.Size, Endianness)
	if err != nil {
		return err
	}

	err = td.FragHeader.Parse(reader)
	if err != nil {
		return err
	}

	td.Elements = make([]Element, 0)
	for {
		var elt Element
		elt, err = Parse(reader, nil, true)
		if err != nil {
			//panic(err)
			return err
		}
		if _, ok := elt.(*BinXMLEOF); ok {
			td.EOFToken = TokenEOF
			break
		}
		td.Elements = append(td.Elements, elt)
	}
	return nil
}

type TemplateDefinition struct {
	Header TemplateDefinitionHeader
	Data   TemplateDefinitionData
}

func (td *TemplateDefinition) Parse(reader io.ReadSeeker) error {
	err := td.Header.Parse(reader)
	if err != nil {
		return err
	}
	backup := BackupSeeker(reader)
	// The following of the structure is located elsewhere in the chunk
	if int64(td.Header.DataOffset) != backup {
		GoToSeeker(reader, int64(td.Header.DataOffset))
	}
	err = td.Data.Parse(reader)
	if err != nil {
		return err
	}
	// If we jumped off to get the template we have to come back because the Data
	// Are still located after
	if int64(td.Header.DataOffset) != backup {
		GoToSeeker(reader, backup)
	}
	return err
}

func (td TemplateDefinition) String() string {
	//return fmt.Sprintf("Template DataOffset: %v\nID: %v\nSize: %v\nFragHeader: %v\nElement: %v\n", td.DataOffset, td.ID, td.Size, td.FragHeader, td.Element)
	return fmt.Sprintf("%T: %s", td, string(ToJSON(td)))
}

////////////////////////// BinXmlTemplateInstanceData //////////////////////////

// TemplateInstanceData structure
type TemplateInstanceData struct {
	NumValues    int32
	ValDescs     []ValueDescriptor
	Values       []Element
	ValueOffsets []int32
}

// Parse Element implementation
func (tid *TemplateInstanceData) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &tid.NumValues, Endianness)
	if err != nil {
		return err
	}
	if tid.NumValues < 0 {
		return fmt.Errorf("Negative number of values in TemplateInstanceData")
	}
	// Cannot definitely not be bigger than MaxSliceSize
	if tid.NumValues > MaxSliceSize {
		return fmt.Errorf("Too many values in TemplateInstanceData")
	}
	// We can now allocate process the values
	tid.Values = make([]Element, tid.NumValues)
	tid.ValueOffsets = make([]int32, tid.NumValues)
	tid.ValDescs = make([]ValueDescriptor, tid.NumValues)
	if tid.NumValues > 0 {
		err = encoding.UnmarshaInitSlice(reader, &tid.ValDescs, Endianness)
		if err != nil {
			return err
		}
	}

	// Parse the values
	for i := int32(0); i < tid.NumValues; i++ {
		tid.Values[i], err = ParseValueReader(tid.ValDescs[i], reader)
		if err != nil {
			log.Errorf("%v : %s", tid.ValDescs[i], err)
			log.DebugDontPanicf("%v : %s", tid.ValDescs[i], err)
		}
	}
	return err
}

///////////////////////// BinXMLValue Related Structures ///////////////////////

type ValueDescriptor struct {
	Size    uint16
	ValType ValueType
	Unknown int8 // 0x00
}

func (v ValueDescriptor) String() string {
	return fmt.Sprintf("Size: %d ValType: 0x%02x Unk: 0x%02x", v.Size, v.ValType, v.Unknown)
}

// The value data depends on the value type
type ValueData []byte

//////////////////////////////// BinXMLEOF /////////////////////////////////////

type BinXMLEOF struct {
	Token int8
}

func (b *BinXMLEOF) Parse(reader io.ReadSeeker) error {
	// TODO: Remove this security later
	/*rs := ReadSeekerSize(reader)
	cur, err := reader.Seek(0, os.SEEK_CUR)
	if err != nil {
		panic(err)
	}
	if rs-cur > 10 {
		log.Errorf("[Remove this message later] probably missing data (%d bytes)", rs-cur)
		DebugReader(reader, 10, 5)
	}
	// Go to end of reader
	//reader.Seek(0, os.SEEK_END)*/
	return encoding.Unmarshal(reader, &b.Token, Endianness)
}

///////////////////////////// BinXmlEntityReference ////////////////////////////

// BinXMLEntityReference implementation
type BinXMLEntityReference struct {
	Token      int8
	NameOffset uint32
	Name       Name
}

// Parse implements Element
func (e *BinXMLEntityReference) Parse(reader io.ReadSeeker) error {
	err := encoding.Unmarshal(reader, &e.Token, Endianness)
	if err != nil {
		return err
	}
	err = encoding.Unmarshal(reader, &e.NameOffset, Endianness)
	if err != nil {
		return err
	}
	o := BackupSeeker(reader)
	// if the Entity Name is just after
	if int64(e.NameOffset) == o {
		return e.Name.Parse(reader)
	}
	// We jump to the right offset
	GoToSeeker(reader, int64(e.NameOffset))
	err = e.Name.Parse(reader)
	// We restore our position
	GoToSeeker(reader, o)
	return err
}

func (e *BinXMLEntityReference) String() string {
	switch e.Name.String() {
	case "amp":
		return "&"
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "quot":
		return "\""
	case "apos":
		return "'"
	}
	return ""
}

///////////////////////////// BinXMLEndElementTag //////////////////////////////

type Token struct {
	Token int8
}

func (t *Token) Parse(reader io.ReadSeeker) error {
	return encoding.Unmarshal(reader, &t.Token, Endianness)
}

type BinXMLEndElementTag struct {
	//Token int8
	Token
}

///////////////////////// TokenCloseStartElementTag ////////////////////////////

type BinXMLCloseStartElementTag struct {
	Token
}

////////////////////////// TokenCloseEmptyElementTag ///////////////////////////

type BinXMLCloseEmptyElementTag struct {
	Token
}

////////////////////////////// EmptyElement ////////////////////////////////////

type EmptyElement struct{}

func (EmptyElement) Parse(reader io.ReadSeeker) error {
	return nil
}
