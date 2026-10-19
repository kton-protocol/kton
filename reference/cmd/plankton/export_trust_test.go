package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// signedFoton returns a foton envelope (in -> out) signed by priv, declaring keyid.
func signedFoton(t *testing.T, priv ed25519.PrivateKey, keyid, inName, inHex, outName, outHex string) core.Envelope {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": outName, "digest": map[string]any{"sha256": outHex}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": inName, "digest": map[string]any{"sha256": inHex}}},
			"protocol": map[string]any{"kind": "run", "ref": "sha256:proto"},
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: keyid, Sig: base64.StdEncoding.EncodeToString(sig)})
	return env
}

// TestExportJSONTrustKeys: the JSON export carries the same per-record verdict as `nekton export` -
// "unchecked" without --trust-keys, "verified" with every trusted key that actually signed, and
// "failed" when the envelope DECLARES a trusted keyid but was signed by another key.
func TestExportJSONTrustKeys(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	_, privX, _ := ed25519.GenerateKey(rand.Reader)
	in := strings.Repeat("11", 32)
	good, cosigned, forged := strings.Repeat("22", 32), strings.Repeat("33", 32), strings.Repeat("44", 32)

	add := func(env core.Envelope) {
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
	}
	add(signedFoton(t, privA, core.KeyIDHex(pubA), "raw.csv", in, "good.csv", good))
	// the same foton signed by two producers: unioned onto ONE record
	add(signedFoton(t, privA, core.KeyIDHex(pubA), "raw.csv", in, "co.csv", cosigned))
	add(signedFoton(t, privB, core.KeyIDHex(pubB), "raw.csv", in, "co.csv", cosigned))
	// declares A's keyid, signed by an untrusted key
	add(signedFoton(t, privX, core.KeyIDHex(pubA), "raw.csv", in, "forged.csv", forged))

	byOut := func(g *exportGraph) map[string]exportFoton {
		m := map[string]exportFoton{}
		for _, f := range g.Fotons {
			if _, dup := m[f.Outputs[0]]; dup {
				t.Fatalf("foton for %s exported twice", f.Outputs[0])
			}
			m[f.Outputs[0]] = f
		}
		return m
	}

	g, err := buildGraph(dir, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	for out, f := range byOut(g) {
		if f.SignerVerified != "unchecked" || len(f.VerifiedSigners) != 0 {
			t.Fatalf("%s without --trust-keys: got %q %v, want unchecked and no signer", out, f.SignerVerified, f.VerifiedSigners)
		}
	}

	g, err = buildGraph(dir, "t", []ed25519.PublicKey{pubA, pubB})
	if err != nil {
		t.Fatal(err)
	}
	m := byOut(g)
	if f := m["sha256:"+good]; f.SignerVerified != "verified" || f.VerifiedSigner != core.KeyIDHex(pubA) {
		t.Fatalf("good: got %q %q", f.SignerVerified, f.VerifiedSigner)
	}
	if f := m["sha256:"+cosigned]; f.SignerVerified != "verified" || len(f.VerifiedSigners) != 2 || len(f.KeyIDs) != 2 {
		t.Fatalf("co-signed: got %q verified=%v keyids=%v, want both producers", f.SignerVerified, f.VerifiedSigners, f.KeyIDs)
	}
	if f := m["sha256:"+forged]; f.SignerVerified != "failed" || f.VerifiedSigner != "" || f.KeyIDs[0] != core.KeyIDHex(pubA) {
		t.Fatalf("forged: got %q %q keyids=%v, want failed with the declared keyid kept", f.SignerVerified, f.VerifiedSigner, f.KeyIDs)
	}
	if f := m["sha256:"+good]; len(f.OutputRefs) != 1 || f.OutputRefs[0].Path != "good.csv" || f.InputRefs[0].Path != "raw.csv" {
		t.Fatalf("refs: got in=%v out=%v", f.InputRefs, f.OutputRefs)
	}
}
