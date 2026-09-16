package registry_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// Adding an EMPTY source to a union must not reduce what the sync API delivers.
//
// OpenUnion zeroes foreign positions on purpose - a number issued by another store means nothing
// here. The position was then reassigned on one settle path only, so a co-signature row, which takes
// the already-seen path and never reaches index(), kept Seq 0. Records(since) answers `Seq > since`,
// so Seq 0 is filtered out of every answer, Records(0) included: the claim still carried both
// signatures in the index, and the feed no longer offered the second one to any peer.
func TestUnionKeepsEverySignatureInTheFeed(t *testing.T) {
	mk := func(b byte) ed25519.PrivateKey {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = b
		}
		return ed25519.NewKeyFromSeed(seed)
	}
	privA, privB := mk(0x41), mk(0x42)

	payload, err := core.CanonValue(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://kton.dev/claim/v0",
		"subject": []any{map[string]any{"uri": "urn:example:thing"}},
		"predicate": map[string]any{"predicate": map[string]any{"uri": "https://e.org/reviewed"},
			"by": "CN=A", "when": "2026-07-16T00:00:00Z"},
	})
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

	// One store holding the claim co-signed by A and B: two lines, one claim id.
	src := t.TempDir()
	r, err := registry.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(sign(privA)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(sign(privB)); err != nil {
		t.Fatal(err)
	}

	signersIn := func(recs []registry.Record) map[string]bool {
		got := map[string]bool{}
		for _, rec := range recs {
			for _, s := range rec.Envelope.Signatures {
				got[s.KeyID] = true
			}
		}
		return got
	}
	kidA := core.KeyIDHex(privA.Public().(ed25519.PublicKey))
	kidB := core.KeyIDHex(privB.Public().(ed25519.PublicKey))

	alone, err := registry.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	base := signersIn(alone.Records(0))
	if !base[kidA] || !base[kidB] {
		t.Fatalf("the source itself does not feed both signatures: %v", base)
	}

	// The union with an EMPTY store must deliver exactly the same evidence.
	u, err := registry.OpenUnion(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got := signersIn(u.Records(0))
	for kid, who := range map[string]string{kidA: "A", kidB: "B"} {
		if !got[kid] {
			t.Errorf("after adding an empty source, the feed no longer carries %s's signature "+
				"(%v) - merely widening a union reduced what the sync API delivers", who, got)
		}
	}

	// Every feed entry must carry a position, or it is held and never offered.
	for i, rec := range u.Records(0) {
		if rec.Seq == 0 {
			t.Errorf("feed entry %d has no position; Records(since) filters it out of every answer", i)
		}
	}
}
