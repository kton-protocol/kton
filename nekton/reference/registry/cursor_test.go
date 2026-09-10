package registry_test

import (
	"crypto/ed25519"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// AUD-04, first half. A co-signature used to reach nobody. The subnekton was REWRITTEN in place, so
// nothing was appended, nothing got a position, and a peer already past the claim never learned that
// a second party had endorsed it.
//
// The subnekton is an append-only log because in nekton the ORDER carries meaning (prev, head,
// seal). Rewriting an entry erased the record that anything had changed - and with it the only thing
// a cursor could have noticed.
func TestACoSignatureReachesAPeerPastTheClaim(t *testing.T) {
	ka, kb := testKey(t), testKey(t)
	dir := t.TempDir()
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	envA := unscopedClaimSignedBy(t, ka)
	if _, _, err := r.Add(envA); err != nil {
		t.Fatal(err)
	}
	cursor := r.MaxSeq() // a peer syncs to here and stores this

	if _, _, err := r.Add(unscopedClaimSignedBy(t, kb)); err != nil {
		t.Fatal(err)
	}
	delivered := r.Records(cursor)
	if len(delivered) == 0 {
		t.Fatal("a peer at the pre-co-signature cursor is handed nothing - the co-signature is lost to it")
	}
	if r.MaxSeq() <= cursor {
		t.Errorf("the cursor did not move (%d), so the record just delivered is not covered by it and "+
			"would be handed out again on every sync, forever", r.MaxSeq())
	}
	// Syncing again with the NEW cursor must be quiet: the peer is up to date.
	if n := len(r.Records(r.MaxSeq())); n != 0 {
		t.Errorf("re-syncing at the returned cursor still returns %d record(s)", n)
	}
	// And the peer, having unioned what it received, ends up with both signatures.
	id := envID(t, envA)
	peer, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range r.Records(0) {
		if _, _, err := peer.Add(rec.Envelope); err != nil {
			t.Fatalf("a peer refused a record we served it: %v", err)
		}
	}
	got, ok := peer.Claim(id)
	if !ok {
		t.Fatal("the peer does not hold the claim")
	}
	if n := len(got.Envelope.Signatures); n != 2 {
		t.Errorf("the peer ended up with %d signature(s), want 2", n)
	}
	for name, k := range map[string]ed25519.PrivateKey{"A": ka, "B": kb} {
		if ok, _ := got.Envelope.Verify(k.Public().(ed25519.PublicKey)); !ok {
			t.Errorf("signer %s does not verify against what the peer assembled", name)
		}
	}
	_ = core.PayloadType
}

// AUD-04, second half, and it is not a numbering problem: the FEED was hiding a record the STORE was
// holding. A claim whose seed is missing is persisted and structurally valid - incomplete is not
// invalid (§11) - but it was absent from the feed, so a peer never received it. When the seed later
// arrived and it resolved locally, it entered the index at its ORIGINAL position, below every cursor
// already issued, and was never delivered either.
func TestADeferredClaimIsOfferedAndAnswersNothing(t *testing.T) {
	k := testKey(t)
	seed := seedClaim(t, k)
	seedID := envID(t, seed)
	child := scopedClaim(t, k, "child", seedID, seedID)
	childID := envID(t, child)

	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(child); err != nil {
		t.Fatal(err) // persisted, deferred: its seed is not held
	}

	t.Run("it is in the feed", func(t *testing.T) {
		found := false
		for _, rec := range r.Records(0) {
			if rec.ClaimID == childID {
				found = true
			}
		}
		if !found {
			t.Error("a held record is missing from sync(0); a peer can never receive it, and once it " +
				"resolves locally it sits below every cursor already issued")
		}
		if r.Deferred() != 1 {
			t.Errorf("Deferred() = %d, want 1", r.Deferred())
		}
	})

	t.Run("it answers no query", func(t *testing.T) {
		if _, ok := r.Claim(childID); ok {
			t.Error("an unresolved claim answered Claim()")
		}
		if r.Len() != 0 {
			t.Errorf("Len() = %d: an unresolved claim must not count as held", r.Len())
		}
		if _, chain, _ := r.Heads(seedID); chain != 0 {
			t.Errorf("chain length %d: an unresolved claim must not join a resolved head (§7.4)", chain)
		}
	})

	t.Run("a peer that received it resolves it itself", func(t *testing.T) {
		peerDir := t.TempDir()
		peer, err := registry.Open(peerDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range r.Records(0) { // everything offered while unresolved
			if _, _, err := peer.Add(rec.Envelope); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := peer.Add(seed); err != nil { // the dependency arrives at the peer
			t.Fatal(err)
		}
		// A deferred claim resolves on the next open (settle runs there), which is why the peer
		// needed the bytes BEFORE the seed arrived - the whole point of offering it.
		reopened, err := registry.Open(peerDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reopened.Claim(childID); !ok {
			t.Error("the peer holds both the child and its seed but cannot resolve the chain")
		}
	})
}
