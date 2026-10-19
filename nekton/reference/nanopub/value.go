package nanopub

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"kton.dev/plankton/core"
)

// A claim object field may hold a structured value - an object or a list - and nekton signs it as
// such. The RDF projection used to print it with Go's %v, so `{"role": "step"}` arrived in the
// published graph as the literal "map[role:step]": signed, but unreachable by any query (K8).
//
// unfold is the ONE walk both projections take (renderTrig for TriG, nanopubQuads for the signed
// nanopublication), so what is signed and what is published cannot drift apart. A nested object
// becomes its own node, named by its path under the nanopublication's base - "o.value" for the
// object under field "value" - rather than a blank node: named nodes canonicalize without blank-node
// labelling, which the Trusty URI computation does not do. A list repeats the field once per item;
// items that are objects are named by their index ("o.files.0").

// prop is one property of an object node: either a scalar (rendered through hashRef / refTerm, as
// before) or a reference to a child node. Flat string-valued claims project byte-for-byte as they
// did; a number does not (scalarText writes it without exponent), so neither does its Trusty URI.
type prop struct {
	node   string // path of the node this property is on, "o" for the claim object
	field  string // field key, resolved to an IRI by the caller
	scalar string // the value's text, when it is not structured
	child  string // path of the child node, when it is
}

func unfold(node string, obj map[string]any) []prop {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []prop
	for _, k := range keys {
		out = append(out, unfoldValue(node, k, node+"."+segment(k), obj[k])...)
	}
	return out
}

func unfoldValue(node, field, path string, v any) []prop {
	switch x := v.(type) {
	case map[string]any:
		return append([]prop{{node: node, field: field, child: path}}, unfold(path, x)...)
	case []any:
		var out []prop
		for i, item := range x {
			out = append(out, unfoldValue(node, field, path+"."+strconv.Itoa(i), item)...)
		}
		return out
	default:
		return []prop{{node: node, field: field, scalar: scalarText(v)}}
	}
}

// segment is a field key as a node-name segment. A key that is not a plain name is replaced by a
// stable digest of itself, so a crafted key can never break out of the node IRI in either projection.
//
// Digest segments carry the reserved prefix "_k", and a plain key with that prefix is digested too,
// so a digest can never equal a plain key: two different objects can only share a node name through
// a collision of the 128-bit digest. (A bare "k"+48 bits was itself a valid plain key.)
func segment(k string) string {
	if safePNLocal(k) && !strings.ContainsAny(k, ".") && !strings.HasPrefix(k, "_k") {
		return k
	}
	return "_k" + core.HashBytes([]byte(k))[7:39]
}

// scalarText is the text of a JSON scalar. Numbers keep their literal form (json.Number) or are
// written without exponent; everything else as before.
func scalarText(v any) string {
	switch x := v.(type) {
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return "null" // JSON null; %v wrote Go's "<nil>"
	default:
		return fmt.Sprintf("%v", v)
	}
}
