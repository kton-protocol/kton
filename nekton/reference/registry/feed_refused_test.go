package registry_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// index() used to return nothing, so settle could not learn that indexing had REFUSED a record. It
// was appended to the feed and progress was marked anyway, so `records --json` and the JSON export
// republished claims this store itself will not serve: a peer refuses them in turn, and a source
// that looks usable delivers an incomplete import. Dropped() did not count them either, so the
// number said everything had arrived.
//
// This is nekton's half of the boundary problem and it is not plankton's: there the RULES were
// missing at ingest, here the rules are shared already and the PLUMBING was missing. The two kernels
// have no validation in common below the envelope layer - a claim has no inputs, a foton has no prev.
func TestRefusedRecordsDoNotReachTheFeed(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x5c
	}
	priv := ed25519.NewKeyFromSeed(seed)

	payload, err := core.CanonValue(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://kton.dev/claim/v0",
		"subject": []any{map[string]any{"uri": "urn:example:thing"}},
		"predicate": map[string]any{"predicate": map[string]any{"uri": "https://e.org/p"},
			"by": "CN=A", "when": "2026-07-16T00:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	good := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	good.Signatures = append(good.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)})

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := r.Add(good)
	if err != nil {
		t.Fatal(err)
	}

	// A correctly addressed record with an EMPTY signature array, appended straight to the store -
	// which a git merge, a documented federation transport, does without ever calling Add.
	unsigned := good
	unsigned.Signatures = nil
	line, err := json.Marshal(map[string]any{"claimId": id + "x", "envelope": unsigned})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")
	fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("no subnekton: %v", err)
	}
	if _, err := fh.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// It must not be answerable...
	if _, ok := r2.Claim(id + "x"); ok {
		t.Error("an unsigned record is answerable by id")
	}
	// ...and it must not be offered to a peer either.
	for _, rec := range r2.Records(0) {
		if len(rec.Envelope.Signatures) == 0 {
			t.Errorf("the feed offers a record the index refused (%s) - a peer will refuse it, so "+
				"this source looks usable and delivers an incomplete import", rec.ClaimID)
		}
	}
	if n := len(r2.Records(0)); n != 1 {
		t.Errorf("feed holds %d records, want only the good one", n)
	}
	// And the count must say something was dropped, rather than reporting a clean load.
	if r2.Dropped() == 0 {
		t.Error("Dropped() reports 0 while a record was refused - the number says everything arrived")
	}
}
