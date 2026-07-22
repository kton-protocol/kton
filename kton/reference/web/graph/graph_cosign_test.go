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

func keyFromLabel(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

// TestVerifyChecksAllSignatures: a claim co-signed [foreign, trusted] has a FOREIGN Signatures[0] but
// a TRUSTED co-signer. The viewer must read it as verified (checking all signatures, not just the
// first) and attribute it to the verifying key. Regression for the Signatures[0]-only verify path.
func TestVerifyChecksAllSignatures(t *testing.T) {
	const subjectHash = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	foreign := keyFromLabel("foreign-cosigner")
	trusted := keyFromLabel("trusted-cosigner")
	fp := foreign.Public().(ed25519.PublicKey)
	tp := trusted.Public().(ed25519.PublicKey)

	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"sha256": subjectHash}}},
		"predicateType": "https://kton.dev/claim/v0",
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/claim/v0/reviewed"},
			"by":        "someone",
			"object":    map[string]any{"decision": "approve"},
		},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	canon, err := core.CanonJSON(raw)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	pae := core.PAE(core.PayloadType, canon)
	rec := map[string]any{
		"claimId": core.HashBytes(canon),
		"envelope": map[string]any{
			"payloadType": core.PayloadType,
			"payload":     base64.StdEncoding.EncodeToString(canon),
			"signatures": []any{ // foreign FIRST, so Signatures[0] is the untrusted key
				map[string]any{"keyid": core.KeyIDHex(fp), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(foreign, pae))},
				map[string]any{"keyid": core.KeyIDHex(tp), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(trusted, pae))},
			},
		},
	}
	union, _ := json.Marshal([]any{rec})
	keys, _ := json.Marshal(map[string]string{core.KeyIDHex(tp): hex.EncodeToString(tp)}) // only trusted key is known

	out, err := BuildGraph(string(union), string(keys), "{}")
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	var g struct {
		Nodes []struct {
			Type     string `json:"type"`
			Verified bool   `json:"verified"`
			Signer   string `json:"signer"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatalf("unmarshal graph: %v", err)
	}

	var seen bool
	for _, n := range g.Nodes {
		if n.Type != "claim" {
			continue
		}
		seen = true
		if !n.Verified {
			t.Error("co-signed claim with a trusted co-signer must read verified=true")
		}
		if n.Signer != core.KeyIDHex(tp) {
			t.Errorf("verified claim must be attributed to the verifying key %s, got %s", core.KeyIDHex(tp), n.Signer)
		}
	}
	if !seen {
		t.Fatal("no claim node produced")
	}
}
