package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestTrustedRekorPubRefusesUnpinnedCustom: a custom Rekor endpoint (attacker-controllable
// PLANKTON_REKOR_URL) with NO pinned key must be refused - otherwise a fabricated entry, signed by the
// endpoint's own key and checked against that same self-served key, would "verify". A PINNED key
// (PLANKTON_REKOR_PUBKEY) is always honored, for any URL.
func TestTrustedRekorPubRefusesUnpinnedCustom(t *testing.T) {
	t.Setenv("PLANKTON_REKOR_PUBKEY", "")
	if _, err := trustedRekorPub("http://attacker.example"); err == nil {
		t.Fatal("a custom Rekor endpoint without a pinned key must be refused")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLANKTON_REKOR_PUBKEY", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	got, err := trustedRekorPub("http://attacker.example")
	if err != nil || got == nil {
		t.Fatalf("a pinned key must be accepted even for a custom URL: %v", err)
	}
	if !got.Equal(&k.PublicKey) {
		t.Fatal("the pinned key must be the one used")
	}
}
