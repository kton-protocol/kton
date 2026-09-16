package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// The JSON export iterated the ARRIVAL FEED. Two envelopes carrying the same payload signed by
// different keys are two feed entries with ONE claim id, so one logical claim exported as two rows -
// same claimId, and with only one key trusted, contradictory signerVerified. A consumer keying a map
// by claim id kept whichever row happened to come second, which made the projection depend on
// arrival order rather than on evidence.
//
// One claim is one row, and the trust answer is computed over every signature the merged record
// carries - a co-signed claim with two trusted signers is the case four-eyes rests on, and reporting
// one of them loses exactly the fact that matters.
func TestExportEmitsOneRowPerClaim(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")

	mk := func(b byte) (ed25519.PrivateKey, ed25519.PublicKey) {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = b
		}
		p := ed25519.NewKeyFromSeed(seed)
		return p, p.Public().(ed25519.PublicKey)
	}
	privA, pubA := mk(0x11)
	privB, pubB := mk(0x22)

	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://kton.dev/claim/v0",
		"subject":       []any{map[string]any{"uri": "urn:example:thing"}},
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://example.org/terms/reviewed"},
			"by":        "CN=A", "when": "2026-07-16T00:00:00Z",
		},
	}
	payload, err := core.CanonValue(stmt)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(priv ed25519.PrivateKey) core.Envelope {
		sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
		e := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		e.Signatures = append(e.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)})
		return e
	}

	r, err := registry.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	idA, _, err := r.Add(sign(privA))
	if err != nil {
		t.Fatal(err)
	}
	idB, _, err := r.Add(sign(privB))
	if err != nil {
		t.Fatal(err)
	}
	if idA != idB {
		t.Fatalf("the two envelopes should share a claim id: %s vs %s", idA, idB)
	}

	// Only A is trusted, which is what made the two rows contradict each other.
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "a.pub"), []byte(hex.EncodeToString(pubA)), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "claims.json")
	if err := func() error { t.Setenv("NEKTON_DIR", reg); return run("export", []string{"--trust-keys", keys, out}) }(); err != nil {
		t.Fatalf("export: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Claims []struct {
			ClaimID         string   `json:"claimId"`
			KeyIDs          []string `json:"keyids"`
			VerifiedSigners []string `json:"verifiedSigners"`
			// A string, not a bool: without --trust-keys nothing is checked, and `false` then reads
			// as CHECKED AND FAILED rather than NOBODY LOOKED. Here a key IS trusted, so the
			// expected value is "verified".
			SignerVerified string `json:"signerVerified"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("export is not valid JSON: %v\n%s", err, b)
	}
	if len(got.Claims) != 1 {
		ids := []string{}
		for _, c := range got.Claims {
			ids = append(ids, c.ClaimID)
		}
		t.Fatalf("export has %d rows for one claim (%s) - the projection is the arrival feed, not the claims",
			len(got.Claims), strings.Join(ids, ", "))
	}
	c := got.Claims[0]
	if len(c.KeyIDs) != 2 {
		t.Errorf("keyids = %v, want both declared signers", c.KeyIDs)
	}
	if c.SignerVerified != "verified" || len(c.VerifiedSigners) != 1 || c.VerifiedSigners[0] != core.KeyIDHex(pubA) {
		t.Errorf("verifiedSigners = %v (signerVerified=%v), want exactly the trusted key %s",
			c.VerifiedSigners, c.SignerVerified, core.KeyIDHex(pubA))
	}
	_ = pubB
}
