package rdf

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// The per-record projection (#232), for an index that stores each record once and decides trust at
// query time.
//
// Turtle answers "the lineage, under these keys" as one document: attribution is decided by the keys
// passed in, so an index that serves several trust sets has to store one projection per set. Here
// the two parts are apart:
//
//   - Record is the foton's own quads. It takes no keys, so it is a function of the record alone and
//     the same bytes on every machine. It covers exactly one foton; lineage is composed in the store.
//   - Attribution is one named graph per given key that verifies the foton's envelope. A consumer
//     passes every key it knows, stores every graph it gets back, and includes the graphs of the keys
//     it trusts in a query.
//
// No attribution graph means unverified. Neither nk:signerVerified false nor nk:claimedSigner (the
// envelope's unauthenticated keyid hint) appears in this form.
//
// Output is canonical N-Quads: full IRIs, one quad per line, sorted, no duplicates.

const (
	rdfNsRDF         = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	rdfNsXSD         = "http://www.w3.org/2001/XMLSchema#"
	rdfNsAttribution = "https://kton.dev/attribution/"
)

// RecordGraph is the named graph that holds a foton's own quads: the foton's own IRI.
func RecordGraph(fotonID string) string { return iriOf(fotonID) }

// AttributionGraph is the named graph that holds the attribution of a foton to one key.
func AttributionGraph(fotonID, keyid string) string {
	return rdfNsAttribution + strings.TrimPrefix(fotonID, "sha256:") + "/" + keyid
}

// Record returns the foton's own quads as canonical N-Quads, in graph RecordGraph(fotonID).
func Record(r *registry.Registry, fotonID string) ([]byte, error) {
	id, ok := core.NormalizeContentHash(fotonID)
	if !ok {
		return nil, fmt.Errorf("%q is not a foton id", fotonID)
	}
	f, ok := r.Foton(id)
	if !ok {
		return nil, fmt.Errorf("no foton %s in the registry", id)
	}
	act, g := iriOf(id), RecordGraph(id)
	var q nquads
	q.add(act, rdfNsRDF+"type", iri(rdfNsProv+"Activity"), g)
	q.add(act, rdfNsNK+"protocolKind", lit(f.Protocol.Kind, ""), g)
	if ref := iriOf(f.Protocol.Ref); ref != "" {
		q.add(act, rdfNsNK+"protocolRef", iri(ref), g)
	}
	if envh, ok := f.Protocol.Descriptor["environment"].(string); ok {
		if en := iriOf(envh); en != "" {
			q.add(act, rdfNsNK+"environment", iri(en), g)
		}
	}
	// A conditional foton (#212) says so in its own quads: it is a fact about the record, not about
	// who signed it. Each condition is a node named under the foton, so the bytes stay stable.
	if f.Conditional() {
		q.add(act, rdfNsNK+"conditional", lit("true", rdfNsXSD+"boolean"), g)
		for i, c := range f.Protocol.Conditions {
			cn := fmt.Sprintf("%s#condition-%d", act, i)
			q.add(act, rdfNsNK+"condition", iri(cn), g)
			q.add(cn, rdfNsNK+"conditionKind", lit(c.Kind, ""), g)
			if c.Ref != "" {
				q.add(cn, rdfNsNK+"conditionRef", lit(c.Ref, ""), g)
			}
		}
	}
	for _, in := range f.Inputs {
		if n := iriOf(in.Hash); n != "" {
			q.add(act, rdfNsProv+"used", iri(n), g)
			q.add(n, rdfNsRDF+"type", iri(rdfNsProv+"Entity"), g)
			if in.Path != "" {
				q.add(n, rdfNsRDFS+"label", lit(in.Path, ""), g)
			}
		}
	}
	for _, o := range f.Outputs {
		on := iriOf(o.Hash)
		if on == "" {
			continue
		}
		q.add(on, rdfNsRDF+"type", iri(rdfNsProv+"Entity"), g)
		q.add(on, rdfNsProv+"wasGeneratedBy", iri(act), g)
		if o.Path != "" {
			q.add(on, rdfNsRDFS+"label", lit(o.Path, ""), g)
		}
		for _, in := range f.Inputs {
			if n := iriOf(in.Hash); n != "" {
				q.add(on, rdfNsProv+"wasDerivedFrom", iri(n), g)
			}
		}
	}
	return q.bytes(), nil
}

// Attribution returns, for every key in keys that verifies the foton's envelope, that key's
// attribution as canonical N-Quads in graph AttributionGraph(fotonID, keyid). A co-signed foton has
// one entry per verifying producer. A key listed twice is one entry.
func Attribution(r *registry.Registry, fotonID string, keys []ed25519.PublicKey) (map[string][]byte, error) {
	id, ok := core.NormalizeContentHash(fotonID)
	if !ok {
		return nil, fmt.Errorf("%q is not a foton id", fotonID)
	}
	env, ok := r.Envelope(id)
	if !ok {
		return nil, fmt.Errorf("no foton %s in the registry", id)
	}
	out := map[string][]byte{}
	for _, pub := range keys {
		if ok, err := env.Verify(pub); !ok || err != nil {
			continue
		}
		kid := core.KeyIDHex(pub)
		g := AttributionGraph(id, kid)
		var q nquads
		q.add(iriOf(id), rdfNsProv+"wasAttributedTo", iri(rdfNsAgent+kid), g)
		q.add(iriOf(id), rdfNsNK+"signerVerified", lit("true", rdfNsXSD+"boolean"), g)
		out[kid] = q.bytes()
	}
	return out, nil
}

// iriOf is the full IRI of a content hash (https://kton.dev/o/<hex>), or "" for anything that is not
// one - the same guard pkNode gives the Turtle face.
func iriOf(hash string) string {
	n, ok := core.NormalizeContentHash(hash)
	if !ok {
		return ""
	}
	return rdfNsPK + strings.TrimPrefix(n, "sha256:")
}

type term struct {
	v     string
	isLit bool
	dtype string
}

func iri(s string) term        { return term{v: s} }
func lit(s, dtype string) term { return term{v: s, isLit: true, dtype: dtype} }

type nquads struct{ lines []string }

// add appends one quad. Every IRI here is built from a validated content hash, a validated keyid or a
// fixed vocabulary term, so none can carry a character N-Quads forbids in an IRI.
func (q *nquads) add(s, p string, o term, g string) {
	obj := "<" + o.v + ">"
	if o.isLit {
		obj = nqLiteral(o.v)
		if o.dtype != "" {
			obj += "^^<" + o.dtype + ">"
		}
	}
	q.lines = append(q.lines, "<"+s+"> <"+p+"> "+obj+" <"+g+"> .")
}

func (q *nquads) bytes() []byte {
	sort.Strings(q.lines)
	var b strings.Builder
	for i, l := range q.lines {
		if i > 0 && l == q.lines[i-1] {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// nqLiteral renders s as an N-Quads string literal: the four named escapes, and every other control
// character as \uXXXX, so a path or a condition ref can never end the literal or the line.
func nqLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
