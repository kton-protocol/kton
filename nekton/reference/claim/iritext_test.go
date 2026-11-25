package claim

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

// kton-review N1/N2 on #314: every IRI the payload carries is refused before signing if it is no
// IRI as written - the predicate and context always, a subject uri when it starts with a scheme.
func TestSignRefusesNonIRIText(t *testing.T) {
	s := sha256.Sum256([]byte("iritext"))
	k := ed25519.NewKeyFromSeed(s[:])
	sign := func(subject, pred string) error {
		_, _, err := SignWith(Spec{Subject: []SubjectSpec{{URI: subject}}, Predicate: pred,
			By: "r", When: "2026-11-25T00:00:00Z"}, k)
		return err
	}
	for _, c := range []struct{ subject, pred string }{
		{"urn:doc:1", "https://example.org/a b"},
		{"urn:doc:1", "https://example.org/a\tb"},
		{"urn:doc:1", "https://example.org/a\u001bb"},
		{"urn:doc:1", "https://example.org/a<b"},
		{"https://example.org/a b", "https://example.org/p"},
		{"urn:x:%zz", "https://example.org/p"},
		{"urn:x:a b", "https://example.org/p"},
	} {
		if err := sign(c.subject, c.pred); err == nil || !strings.Contains(err.Error(), "no IRI as written") {
			t.Errorf("subject %q predicate %q: %v", c.subject, c.pred, err)
		}
	}
	// A subject that does not claim to be an IRI stays signable (SPEC §7.1: a Ref uri is a string).
	for _, c := range []struct{ subject, pred string }{
		{"kton video", "https://example.org/p"},
		{"urn:doc:1", "https://example.org/a%20b"},
		{"urn:x:%25zz", "https://example.org/p"},
		{"urn:x:prüfung", "qa:reviewed"},
	} {
		if err := sign(c.subject, c.pred); err != nil {
			t.Errorf("subject %q predicate %q refused: %v", c.subject, c.pred, err)
		}
	}
}
