package registry_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// A crash mid-append leaves a TORN final line with no newline. Losing that line is correct - it was
// never acknowledged. Losing the NEXT one is not: an O_APPEND write landed directly on the torn
// fragment, concatenating them, so the reader discarded both. `Add` had already returned success and
// indexed the claim, and it was gone on the next open - somebody else's interrupted write silently
// consuming an acknowledged one.
func TestAcknowledgedAppendSurvivesATornTail(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x31
	}
	priv := ed25519.NewKeyFromSeed(seed)

	sign := func(who string) core.Envelope {
		payload, err := core.CanonValue(map[string]any{
			"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://kton.dev/claim/v0",
			"subject": []any{map[string]any{"uri": "urn:x:" + who}},
			"predicate": map[string]any{"predicate": map[string]any{"uri": "https://e.org/p"},
				"by": "CN=" + who, "when": "2026-07-16T00:00:00Z"},
		})
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
		e := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		e.Signatures = append(e.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)})
		return e
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(sign("A")); err != nil {
		t.Fatal(err)
	}

	// The interrupted write: a partial record with no newline, exactly what a crash leaves.
	f := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")
	fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("no subnekton to tear: %v", err)
	}
	if _, err := fh.WriteString(`{"claimId":"torn`); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r2.Add(sign("B")); err != nil {
		t.Fatalf("Add B: %v", err)
	}
	live := r2.Len()

	r3, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Len() != live {
		t.Errorf("an acknowledged Add was lost across a restart: in-memory=%d, reopened=%d "+
			"- the torn line swallowed the record appended after it", live, r3.Len())
	}
	if r3.Len() != 2 {
		t.Errorf("reopened registry holds %d claims, want both A and B", r3.Len())
	}
}
