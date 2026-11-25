package nanopub

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

// A claim signed before signing refused it (v0.5.1 and earlier) with predicate has%zz: Record
// refuses it rather than emit N-Quads an RFC 3987 store rejects (kton-cockpit 25.11.: oxigraph
// answered 400 "Invalid IRI percent encoding %zz").
func TestRecordRefusesInvalidPercentEncoding(t *testing.T) {
	k := seedKey("pct")
	payload, err := claim.StatementPayload(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:doc:1"}},
		Predicate: "https://example.test/v/hasXzz", By: "r", When: "2026-11-25T00:00:00Z", Object: map[string]any{"state": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte("hasXzz"), []byte("has%zz"), 1)
	env, _, err := claim.Seal(payload, ed25519.Sign(k, core.PAE(core.PayloadType, payload)), k.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Record(NewRecordContext(template.Set{}), env)
	if err == nil || !strings.Contains(err.Error(), "has%zz") {
		t.Fatalf("Record = %v, output:\n%s", err, out)
	}
}
