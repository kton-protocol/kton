package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"kton.dev/plankton/core"
)

// signedLocatedAt builds a signed `located-at` claim record asserting subjectHash -> uri, signed by
// the Ed25519 key derived deterministically from keyLabel. It returns the record as a generic JSON
// map (the shape BuildGraph parses), the signer's public-key hex, and its keyid.
func signedLocatedAt(t *testing.T, keyLabel, subjectHash, uri string) (rec map[string]any, pubHex, keyid string) {
	t.Helper()
	seed := sha256.Sum256([]byte(keyLabel))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"sha256": subjectHash}}},
		"predicateType": "https://kton.dev/claim/v0",
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/claim/v0/located-at"},
			"by":        "someone",
			"object":    map[string]any{"uri": uri},
		},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	canon, err := core.CanonJSON(raw)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, canon))
	rec = map[string]any{
		"claimId": core.HashBytes(canon), // the derived id, so the graph accepts it as authentic-id
		"envelope": map[string]any{
			"payloadType": core.PayloadType,
			"payload":     base64.StdEncoding.EncodeToString(canon),
			"signatures": []any{map[string]any{
				"keyid": core.KeyIDHex(pub),
				"sig":   base64.StdEncoding.EncodeToString(sig),
			}},
		},
	}
	return rec, hex.EncodeToString(pub), core.KeyIDHex(pub)
}

// TestLocatorFoldGatedOnVerification: a located-at claim only injects a retrieval locator when its
// signature VERIFIES against a trusted key. An unverified/planted located-at must NOT put an
// attacker-chosen URI into the locator map (the viewer would present it as "where the bytes live").
// Regression for the previously ungated locator fold.
func TestLocatorFoldGatedOnVerification(t *testing.T) {
	const goodHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const evilHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const goodURI = "https://good.example/artifact"
	const evilURI = "https://evil.example/pwn"

	trusted, trustedPub, trustedKeyid := signedLocatedAt(t, "trusted-key", goodHash, goodURI)
	planted, _, plantedKeyid := signedLocatedAt(t, "planted-key", evilHash, evilURI)
	if trustedKeyid == plantedKeyid {
		t.Fatal("expected distinct keyids for the two keys")
	}

	union, err := json.Marshal([]any{trusted, planted})
	if err != nil {
		t.Fatalf("marshal union: %v", err)
	}
	// Only the trusted key is in the verifier's key set; the planted signer is unknown → unverified.
	keys, err := json.Marshal(map[string]string{trustedKeyid: trustedPub})
	if err != nil {
		t.Fatalf("marshal keys: %v", err)
	}

	out, err := BuildGraph(string(union), string(keys), "{}")
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	var g struct {
		Locators map[string][]string `json:"locators"`
	}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatalf("unmarshal graph: %v", err)
	}

	goodKey := goodHash[:shortLen]
	evilKey := evilHash[:shortLen]
	if got := g.Locators[goodKey]; len(got) != 1 || got[0] != goodURI {
		t.Errorf("verified located-at should fold: Locators[%s] = %v, want [%q]", goodKey, got, goodURI)
	}
	if got := g.Locators[evilKey]; len(got) != 0 {
		t.Errorf("unverified located-at must NOT fold (phishing vector): Locators[%s] = %v, want empty", evilKey, got)
	}
}
