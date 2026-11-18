package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"kton.dev/nekton/claim"
)

// Write is the --add path for linked writers: an unscoped claim chains under the root (created on
// the first write), a seed hangs off the root and is registered in it (#213).
func TestWritePlacesUnderTheRoot(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w1, err := r.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:a"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if w1.CreatedRoot == "" || r.Root() != w1.CreatedRoot || r.RootHead() != w1.ID {
		t.Fatalf("first write: %+v, root %s head %s", w1, r.Root(), r.RootHead())
	}
	w2, err := r.Write(claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:nekton:scope:s"}}, PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "s", "genesis": true, "by": "b", "when": "2026-11-18T00:00:00Z"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if w2.CreatedRoot != "" || w2.Registered == "" || r.RootHead() != w2.Registered || !r.Registered()[w2.ID] {
		t.Fatalf("seed write: %+v, head %s, registered %v", w2, r.RootHead(), r.Registered())
	}
	// a claim that names its own scope is left alone
	w3, err := r.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:c"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z", Scope: w2.ID, Prev: w2.ID}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if r.RootHead() != w2.Registered {
		t.Errorf("a claim in subnekton %s moved the root head to %s (%s)", w2.ID, r.RootHead(), w3.ID)
	}
}
