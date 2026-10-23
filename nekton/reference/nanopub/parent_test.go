package nanopub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

func signSeed(t *testing.T, name string, parent map[string]any) core.Envelope {
	t.Helper()
	body := map[string]any{"scope": name, "genesis": true, "by": "k", "when": "2026-10-23T00:00:00Z"}
	if parent != nil {
		body["parent"] = parent
	}
	s := sha256.Sum256([]byte("seeder"))
	env, _, err := claim.SignWith(claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:nekton:scope:" + name}}, PredicateType: claim.ScopePredicateType, PredicateBody: body,
	}, ed25519.NewKeyFromSeed(s[:]))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// A seed's signed parent is in its projection, in every face: the TriG, the signed quads and the
// per-record N-Quads (#239). A seed without one projects as before.
func TestSeedParentIsProjected(t *testing.T) {
	parent := "sha256:" + strings.Repeat("ab", 32)
	c := NewContext(template.Set{}, nil)
	for name, tc := range map[string]struct {
		parent map[string]any
		want   string
	}{
		"by hash": {map[string]any{"hash": parent}, "https://kton.dev/o/" + strings.Repeat("ab", 32)},
		"by uri":  {map[string]any{"uri": "https://example.org/programme"}, "https://example.org/programme"},
	} {
		env := signSeed(t, "study-1", tc.parent)
		st, _, err := claim.ParseEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"scope": "study-1", "parent": tc.parent}
		trig := renderTrig(c, st, body, env, "x", "", "", "")
		if !strings.Contains(trig, "nk:parent") {
			t.Errorf("%s: TriG has no nk:parent:\n%s", name, trig)
		}
		qs := nanopubQuads(c, st, body, env, "x", "", "", "")
		found := false
		for _, q := range qs {
			if strings.HasSuffix(q.p, "parent") && q.o.iri == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: signed quads have no nk:parent %s", name, tc.want)
		}
		own, err := Record(NewRecordContext(template.Set{}), env)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(own), "<https://kton.dev/v/parent> <"+tc.want+">") {
			t.Errorf("%s: per-record quads have no nk:parent:\n%s", name, own)
		}
	}
	own, _ := Record(NewRecordContext(template.Set{}), signSeed(t, "root", nil))
	if strings.Contains(string(own), "parent") {
		t.Errorf("a seed without a parent projects one:\n%s", own)
	}
}
