package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// The normalizer comparison is two-sided (#226). A v0 normalizer without a descriptor keeps its ref as
// written - upper case, or bare hex, both admitted on v0 - and the query may be spelled any way
// NormalizeContentHash accepts. One potential, one answer, whatever the spelling on either side.
func TestNormalizedOutputComparesOneSpelling(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hex := strings.Repeat("ab", 32)
	raw := "sha256:" + strings.Repeat("11", 32)
	for i, ref := range []string{"sha256:" + strings.ToUpper(hex), hex} {
		in := raw
		if i == 1 {
			in = "sha256:" + strings.Repeat("22", 32)
		}
		st := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"name": "canon", "digest": map[string]any{"sha256": strings.Repeat("cc", 32)}}},
			"predicateType": core.PredicateFoton,
			"predicate": map[string]any{
				"inputs":   []any{map[string]any{"name": "raw", "digest": map[string]any{"sha256": strings.TrimPrefix(in, "sha256:")}}},
				"protocol": map[string]any{"kind": "normalize", "ref": ref},
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
		}{core.KeyIDHex(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(core.PayloadType, payload)))})
		if _, _, err := r.Add(env); err != nil {
			t.Fatalf("ref %q: %v", ref, err)
		}
	}
	want := "sha256:" + strings.Repeat("cc", 32)
	for _, in := range []string{raw, "sha256:" + strings.Repeat("22", 32)} {
		for _, q := range []string{"sha256:" + hex, "sha256:" + strings.ToUpper(hex), " sha256:" + hex + " ", hex} {
			if got := r.NormalizedOutput(in, q); got != want {
				t.Errorf("input %s…, query %q: got %q, want %s", in[:13], q, got, want)
			}
		}
	}
}
