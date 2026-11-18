package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
)

// The reserved field replaces projects under nk:replaces, also when an alias file maps the name
// elsewhere: otherwise one registry finds a replacement under one IRI and the next under another
// (#257, review R2).
func TestReplacesIsReservedTerm(t *testing.T) {
	al, err := template.New(nil, []byte(`{"terms": {"replaces": "https://elsewhere.example/supersedes"}}`))
	if err != nil {
		t.Fatal(err)
	}
	old := "sha256:" + strings.Repeat("ab", 32)
	env := signedAbout(t, "urn:werk:a", map[string]any{"replaces": old, "state": "approved"})
	own, err := Record(NewRecordContext(al), env)
	if err != nil {
		t.Fatal(err)
	}
	want := "<https://kton.dev/v/replaces> <https://kton.dev/o/" + strings.Repeat("ab", 32) + ">"
	if !strings.Contains(string(own), want) || strings.Contains(string(own), "elsewhere.example") {
		t.Errorf("own quads lack %s or use the alias:\n%s", want, own)
	}
	st, _, err := claim.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	trig := RenderTrig(NewContext(al, nil), st, map[string]any{"predicate": map[string]any{"uri": "https://kton.dev/v/reviewed"}, "object": map[string]any{"replaces": old}}, env, "x", "", "", "")
	if !strings.Contains(trig, "nk:replaces") || strings.Contains(trig, "elsewhere.example") {
		t.Errorf("TriG does not use nk:replaces:\n%s", trig)
	}
}
