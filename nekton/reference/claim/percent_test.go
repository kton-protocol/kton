package claim

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

// kton-cockpit 25.11.: a predicate or context with a '%' that starts no %XX escape is no IRI; its
// projection fails to load in an RFC 3987 store. It is refused before signing, on both paths.
func TestSignRefusesInvalidPercentEncoding(t *testing.T) {
	s := sha256.Sum256([]byte("pct"))
	k := ed25519.NewKeyFromSeed(s[:])
	base := Spec{Subject: []SubjectSpec{{URI: "urn:doc:1"}}, By: "r", When: "2026-11-25T00:00:00Z"}
	for _, c := range []struct{ pred, ctx string }{
		{"https://example.test/v/has%zz", ""},
		{"https://example.test/v/has%", ""},
		{"https://example.test/v/has%4", ""},
		{"https://example.test/v/ok", "https://example.test/c/%g0"},
	} {
		sp := base
		sp.Predicate, sp.Context = c.pred, c.ctx
		if _, _, err := SignWith(sp, k); err == nil || !strings.Contains(err.Error(), "%XX") {
			t.Errorf("%q / %q: %v", c.pred, c.ctx, err)
		}
	}
	sp := base
	sp.PredicateBody = map[string]any{"predicate": map[string]any{"uri": "https://example.test/v/has%zz"}, "by": "r", "when": base.When}
	if _, _, err := SignWith(sp, k); err == nil {
		t.Error("a PredicateBody with %zz was signed")
	}
	for _, ok := range []string{"https://example.test/v/has%25", "https://example.test/v/a%2Fb", "urn:x:%c3%a4"} {
		sp := base
		sp.Predicate = ok
		if _, _, err := SignWith(sp, k); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}
