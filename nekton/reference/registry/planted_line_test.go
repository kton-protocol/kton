package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

func mkClaim(t *testing.T, priv ed25519.PrivateKey, subject, obj string) (core.Envelope, string) {
	t.Helper()
	env, id, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: subject}},
		Predicate: "https://kton.dev/v/note",
		Object:    map[string]any{"a": obj},
		By:        "CN=t", When: "2026-07-16T00:00:00Z",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env, id
}

// TestPlantedLineDoesNotBecomeTheRecord: two defects with one cause, both reachable from a single
// planted line in a subnekton - the target's `claimId` field carrying a different claim's envelope.
//
//	persistClaim collected every line whose claimId FIELD matched and unioned it. The planted line
//	won (unionSignatures keeps the first when payloads differ), so `merged` became the impostor's
//	envelope and Add returned it as the stored record:
//
//	    Add -> isNew=true  err=<nil>     Len()=0     Claim(target) held=false
//
//	and because Add discarded index()'s refusal, that record was appended to the FEED and served to
//	peers - a false id -> claim binding, refused by the peer in turn, so an import that looks
//	complete is not.
//
// A claim id IS sha256(canon(Statement)). The line either derives its own id or it is not this
// claim. That test is also what preserves the legitimate case, so the last subtest is not garnish.
func TestPlantedLineDoesNotBecomeTheRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plant := func(t *testing.T, dir, underID string, env core.Envelope) {
		t.Helper()
		objs := filepath.Join(dir, "objects")
		if err := os.MkdirAll(objs, 0o755); err != nil {
			t.Fatal(err)
		}
		line, err := json.Marshal(map[string]any{"claimId": underID, "envelope": env})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(objs, "unscoped.nekton.jsonl"), append(line, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("re-ingesting the authentic claim repairs the store", func(t *testing.T) {
		dir := t.TempDir()
		target, targetID := mkClaim(t, priv, "urn:target", "1")
		impostor, impostorID := mkClaim(t, priv, "urn:impostor", "2")
		if targetID == impostorID {
			t.Fatal("same id - nothing is being planted")
		}
		plant(t, dir, targetID, impostor)

		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if r.Len() != 0 {
			t.Fatalf("the planted line was indexed (Len=%d) - the premise is gone", r.Len())
		}
		id, isNew, aerr := r.Add(target)
		if aerr != nil {
			t.Fatalf("re-ingesting the authentic claim: %v", aerr)
		}
		if id != targetID || !isNew {
			t.Errorf("Add returned id=%s isNew=%v", id, isNew)
		}
		if r.Len() != 1 {
			t.Fatalf("Add reported success and the registry holds %d claims", r.Len())
		}
		rec, held := r.Claim(targetID)
		if !held {
			t.Fatal("the claim Add just reported storing cannot be retrieved")
		}
		if rec.Envelope.Payload != target.Payload {
			t.Error("the stored envelope is the planted one, not the authentic claim")
		}

		// A repair that exists only in memory is not a repair.
		r2, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		rec2, held2 := r2.Claim(targetID)
		if !held2 || rec2.Envelope.Payload != target.Payload {
			t.Error("after reopen the authentic claim is gone again")
		}
	})

	t.Run("a refused record never reaches the feed", func(t *testing.T) {
		dir := t.TempDir()
		target, targetID := mkClaim(t, priv, "urn:target", "1")
		impostor, _ := mkClaim(t, priv, "urn:impostor", "2")
		plant(t, dir, targetID, impostor)

		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(target); err != nil {
			t.Fatalf("Add: %v", err)
		}
		// Every feed entry must derive the id it is filed under. A peer that syncs this feed takes
		// the binding on trust, so an entry that fails here is a false binding on the wire.
		for _, rec := range r.Records(0) {
			_, payload, perr := claim.ParseEnvelope(rec.Envelope)
			if perr != nil {
				t.Errorf("feed entry %s does not parse: %v", rec.ClaimID, perr)
				continue
			}
			if derived := claim.ClaimID(payload); derived != rec.ClaimID {
				t.Errorf("the feed offers a FALSE BINDING: stored id %s, envelope derives %s",
					rec.ClaimID, derived)
			}
		}
	})

	t.Run("a genuine co-signature still merges", func(t *testing.T) {
		dir := t.TempDir()
		target, targetID := mkClaim(t, priv, "urn:target", "1")

		// The case unionSignatures is FOR: identical bytes, a second signer. Same payload means the
		// same id, so the identity check must let it through.
		_, priv2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(target.Payload)
		if err != nil {
			t.Fatal(err)
		}
		second := core.Envelope{PayloadType: target.PayloadType, Payload: target.Payload}
		second.Signatures = append(second.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{
			KeyID: core.KeyIDHex(priv2.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv2, core.PAE(target.PayloadType, payload))),
		})

		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(target); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(second); err != nil {
			t.Fatal(err)
		}
		r2, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		rec, held := r2.Claim(targetID)
		if !held {
			t.Fatal("the claim vanished")
		}
		if len(rec.Envelope.Signatures) != 2 {
			t.Errorf("kept %d signatures, want 2 - the identity check must not break co-signing",
				len(rec.Envelope.Signatures))
		}
	})
}
