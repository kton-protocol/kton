package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// Two signers record the same inputs+protocol with different outputs: one action key, two competing
// hits, each with its own declared signer and outputs, and neither checked.
func TestReuseHitsListCompetingMatches(t *testing.T) {
	r, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signers := map[string]string{} // foton id -> keyid
	var ak string
	for _, out := range []string{"22", "33"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		st := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"name": "out", "digest": map[string]any{"sha256": strings.Repeat(out, 32)}}},
			"predicateType": core.PredicateFoton,
			"predicate": map[string]any{
				"inputs":   []any{map[string]any{"name": "in", "digest": map[string]any{"sha256": strings.Repeat("11", 32)}}},
				"protocol": map[string]any{"kind": "run", "ref": "sha256:" + strings.Repeat("aa", 32)},
			},
		}
		payload, err := core.CanonValue(st)
		if err != nil {
			t.Fatal(err)
		}
		env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		env.Signatures = append(env.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{core.KeyIDHex(pub), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(core.PayloadType, payload)))})
		id, _, err := r.Add(env)
		if err != nil {
			t.Fatal(err)
		}
		signers[id] = core.KeyIDHex(pub)
		f, _ := r.Foton(id)
		if ak, err = f.ActionKey(); err != nil {
			t.Fatal(err)
		}
	}
	hits := r.ReuseHits(ak)
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
	outputs := map[string]bool{}
	for _, h := range hits {
		if h.DeclaredSigner != signers[h.FotonID] {
			t.Errorf("hit %s: declared signer %q, want %q", h.FotonID, h.DeclaredSigner, signers[h.FotonID])
		}
		if h.Verification != VerificationUnchecked {
			t.Errorf("hit %s: verification %q, want %q", h.FotonID, h.Verification, VerificationUnchecked)
		}
		if len(h.Outputs) != 1 {
			t.Fatalf("hit %s: outputs %v, want one", h.FotonID, h.Outputs)
		}
		outputs[h.Outputs[0]] = true
	}
	if len(outputs) != 2 {
		t.Errorf("the two hits should carry their two different outputs, got %v", outputs)
	}
	if miss := r.ReuseHits("sha256:" + strings.Repeat("00", 32)); miss == nil || len(miss) != 0 {
		t.Errorf("a miss must be an empty list, not %#v", miss)
	}
}
