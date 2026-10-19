package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

// A structured object value is projected as properties of a named node, not as Go's %v text - and
// the signed quads and the published TriG name the same nodes with the same properties (K8).
func TestStructuredValuesUnfoldTheSameInBothProjections(t *testing.T) {
	body := map[string]any{
		"by": "key:abc", "when": "2026-10-01T00:00:00Z",
		"predicate": map[string]any{"uri": "http://purl.org/dc/terms/isPartOf"},
		"object": map[string]any{"value": map[string]any{
			"role": "step", "step": "aufbereitung", "files": []any{"a.R", map[string]any{"slot": "b"}},
			"evil> . <x": "y",
		}},
	}
	st := &claim.Statement{Subject: []claim.Subject{{Digest: map[string]string{"sha256": strings.Repeat("a", 64)}}}}
	c := NewContext(template.Set{}, nil)
	trig := renderTrig(c, st, body, core.Envelope{}, strings.Repeat("b", 64), "", "", "")
	if strings.Contains(trig, "map[") {
		t.Fatalf("a structured value was printed as Go text:\n%s", trig)
	}
	for _, want := range []string{"sub:o.value", `"step"`, `"aufbereitung"`, "sub:o.value.files.1", `"b"`, `"a.R"`} {
		if !strings.Contains(trig, want) {
			t.Errorf("TriG lacks %s:\n%s", want, trig)
		}
	}
	if strings.Contains(trig, "evil>") {
		t.Errorf("a crafted field key reached the node name raw:\n%s", trig)
	}
	qs := nanopubQuads(c, st, body, core.Envelope{}, strings.Repeat("b", 64), "", "", "")
	nodes := map[string]bool{}
	for _, q := range qs {
		if strings.Contains(q.s, "#o.") {
			nodes[q.s[strings.Index(q.s, "#")+1:]] = true
		}
	}
	for n := range nodes {
		if !strings.Contains(trig, "sub:"+n+" ") {
			t.Errorf("the signed quads have node %s, the TriG does not", n)
		}
	}
	if len(nodes) < 2 {
		t.Errorf("expected nested nodes in the signed quads, got %v", nodes)
	}
}

// A digest segment can never equal a plain key: before, "a b" became "k"+48 bits, which was itself
// a valid plain key, so a claim holding both keys had two different objects on one node.
func TestDigestSegmentsCannotCollideWithPlainKeys(t *testing.T) {
	d := segment("a b")
	if !strings.HasPrefix(d, "_k") || len(d) != 2+32 {
		t.Fatalf("segment(%q) = %q, want _k + 32 hex", "a b", d)
	}
	if got := segment(d); got == d {
		t.Errorf("the digest %q passes as a plain key, so two objects can share a node", d)
	}
	if got := segment("_kplain"); got == "_kplain" {
		t.Error("a plain key with the reserved prefix was kept as is")
	}
	if got := segment("role"); got != "role" {
		t.Errorf("segment(role) = %q, a plain key must stay readable", got)
	}
}

// JSON null is not Go's "<nil>".
func TestNullScalarIsJSONNull(t *testing.T) {
	if got := scalarText(nil); got != "null" {
		t.Errorf("scalarText(nil) = %q, want null", got)
	}
}
