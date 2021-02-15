package evtx

import (
	"fmt"
)

type Node struct {
	Start   *ElementStart
	Element []Element
	Child   []*Node
}

func NodeTree(es []Element, index int) (Node, int) {
	//i := 0
	var n Node
	for index < len(es) {
		e := es[index]
		switch e.(type) {
		case *ElementStart:
			var nn Node
			nn, index = NodeTree(es, index+1)
			nn.Start = e.(*ElementStart)
			n.Child = append(n.Child, &nn)
		case *BinXMLEndElementTag, *BinXMLCloseEmptyElementTag:
			return n, index
		case *BinXMLCloseStartElementTag:
			break
		default:
			n.Element = append(n.Element, e)
		}
		index++
	}
	return n, index
}

// TODO: Not used
func ElementToGoEvtx(elt Element) (GoEvtxElement, error) {
	switch elt.(type) {
	// BinXML specific
	case *ValueText:
		return elt.(*ValueText).String(), nil
	/*case *OptionalSubstitution:
		s := elt.(*OptionalSubstitution)
		return ElementToGoEvtx(ti.Data.Values[int(s.SubID)])
	case *NormalSubstitution:
		s := elt.(*NormalSubstitution)
		return ElementToGoEvtx(ti.Data.Values[int(s.SubID)])
	*/
	case *Fragment:
		temp := elt.(*Fragment).BinXMLElement.(*TemplateInstance)
		root := temp.Root()
		return temp.NodeToGoEvtx(&root)
	case *TemplateInstance:
		temp := elt.(*TemplateInstance)
		root := temp.Root()
		return temp.NodeToGoEvtx(&root)
	case Value:
		return elt.(Value).Repr(), nil
	default:
		return nil, fmt.Errorf("Don't know how to handle: %T", elt)
	}
}
