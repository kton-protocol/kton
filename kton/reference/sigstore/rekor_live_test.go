//go:build live

// Live integration test against the PUBLIC Sigstore Rekor transparency log. It is gated behind
// the `live` build tag so ordinary `go test` never touches the network:
//
//	go test -tags live -run TestRekorLiveAnchor -v ./sigstore
//
// It anchors an obviously-labelled test statement signed with a throwaway ephemeral key - the
// entry becomes a permanent public log record, so nothing sensitive is used. It then fetches the
// entry back and verifies BOTH the Merkle inclusion proof (entry is committed to the tree) and
// the Signed Entry Timestamp (Rekor attested it) against Rekor's published public key - the exact
// checks an independent auditor would run.
package sigstore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"kton.dev/kton/sigstore"
	"kton.dev/plankton/core"
)

func TestRekorLiveAnchor(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// An obviously-test in-toto statement (this goes into the PUBLIC log forever).
	body := []byte("plankton sigstore live test - throwaway ephemeral key, no real subject")
	sum := sha256.Sum256(body)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "plankton-rekor-livetest", "digest": map[string]any{"sha256": hex.EncodeToString(sum[:])}}},
		"predicateType": "https://kton.dev/foton/v0",
		"predicate":     map[string]any{"note": "plankton Rekor live test", "kind": "test"},
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
	}{KeyID: "livetest", Sig: base64.StdEncoding.EncodeToString(sig)})

	verifierPEM, err := sigstore.Ed25519VerifierPEM(pub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Anchor: Rekor re-verifies our DSSE signature and, on success, commits the entry.
	entry, err := sigstore.Anchor("", env, verifierPEM)
	if err != nil {
		t.Fatalf("anchor to public Rekor failed: %v", err)
	}
	t.Logf("anchored: uuid=%s logIndex=%d integratedTime=%s", entry.UUID, entry.LogIndex, time.Unix(entry.IntegratedTime, 0).UTC())

	// 2. Fetch it back independently.
	got, err := sigstore.GetByUUID("", entry.UUID)
	if err != nil {
		t.Fatalf("fetch entry back: %v", err)
	}

	// 3. Verify the SET (Rekor's ECDSA signature over the entry bundle) against Rekor's key.
	rekorPub, err := sigstore.PublicKey("")
	if err != nil {
		t.Fatalf("fetch Rekor public key: %v", err)
	}
	if err := got.VerifySET(rekorPub); err != nil {
		t.Fatalf("SET verification: %v", err)
	}
	t.Log("SET verified against Rekor's public key (Rekor attested this entry at integratedTime)")

	// 4. Verify the Merkle inclusion proof reconstructs the log root.
	if err := got.VerifyInclusion(); err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	t.Log("inclusion proof verified - the entry is committed in the public transparency log")
}
