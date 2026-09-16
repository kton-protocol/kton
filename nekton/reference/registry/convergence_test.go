package registry_test

import (
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// SYNC CONVERGENCE, as a property rather than a scenario.
//
// §12's cursor exists to make one promise: follow it and you lose nothing. The audit's closing note
// is that a full rescan can recover what an incremental follow cannot - so the thing to
// assert is the CONSUMER'S FINAL STATE after repeatedly following the returned cursor, not that some
// counter went up.
//
// The interleavings below are the ones that broke it: a co-signature arriving after the peer is
// already past the claim, and a chain whose dependency arrives out of order. A peer that only ever
// follows the cursor must end up holding exactly what a peer reading everything from zero holds.
func TestFollowingTheCursorConvergesToTheWholeStore(t *testing.T) {
	ka, kb := testKey(t), testKey(t)
	seed := seedClaim(t, ka)
	seedID := envID(t, seed)

	// Each step is one write at the source. The peer syncs after every step, following only the
	// cursor it was handed.
	steps := []struct {
		name string
		env  core.Envelope
	}{
		{"a plain claim", unscopedClaimSignedBy(t, ka)},
		{"a child whose seed is not here yet", scopedClaim(t, ka, "early child", seedID, seedID)},
		{"an unrelated claim", scopedClaim(t, kb, "unrelated", "", "")},
		{"the seed, arriving late", seed},
		{"a co-signature on the plain claim", unscopedClaimSignedBy(t, kb)},
		{"a second child, now resolvable", scopedClaim(t, ka, "later child", seedID, seedID)},
	}

	srcDir, peerDir := t.TempDir(), t.TempDir()
	src, err := registry.Open(srcDir)
	if err != nil {
		t.Fatal(err)
	}

	cursor := 0
	for _, step := range steps {
		if _, _, err := src.Add(step.env); err != nil {
			// A step the source itself refuses is not part of the store, so it is not part of what
			// must converge. Say so rather than silently skipping it.
			t.Logf("source refused %q: %v", step.name, err)
			continue
		}
		// Reopen the source: a deferred claim resolves on the next open, which is exactly the
		// transition that used to strand a record below every issued cursor.
		if src, err = registry.Open(srcDir); err != nil {
			t.Fatal(err)
		}
		peer, err := registry.Open(peerDir)
		if err != nil {
			t.Fatal(err)
		}
		batch := src.Records(cursor)
		for _, rec := range batch {
			if _, _, err := peer.Add(rec.Envelope); err != nil {
				t.Fatalf("after %q the peer refused a record the source served it: %v", step.name, err)
			}
		}
		cursor = src.MaxSeq()
		// Following the SAME cursor again must be quiet: what was delivered is covered by it.
		if n := len(src.Records(cursor)); n != 0 {
			t.Errorf("after %q, re-syncing at the returned cursor still returns %d record(s) - the "+
				"cursor does not cover what it just handed out", step.name, n)
		}
	}

	// The peer followed only cursors. A second peer reads everything from zero. They must agree.
	followed, err := registry.Open(peerDir)
	if err != nil {
		t.Fatal(err)
	}
	fullDir := t.TempDir()
	full, err := registry.Open(fullDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range src.Records(0) {
		if _, _, err := full.Add(rec.Envelope); err != nil {
			t.Fatal(err)
		}
	}
	if full, err = registry.Open(fullDir); err != nil {
		t.Fatal(err)
	}

	if followed.Len() != full.Len() {
		t.Fatalf("the cursor-following peer holds %d claims, the full-read peer %d - following the "+
			"cursor lost something a rescan would have found", followed.Len(), full.Len())
	}
	for _, rec := range full.Records(0) {
		got, ok := followed.Claim(rec.ClaimID)
		if !ok {
			if _, resolvable := full.Claim(rec.ClaimID); !resolvable {
				continue // deferred at both: agreement, not a loss
			}
			t.Errorf("claim %s is resolvable after a full read but not after following the cursor", rec.ClaimID)
			continue
		}
		want, _ := full.Claim(rec.ClaimID)
		if len(got.Envelope.Signatures) != len(want.Envelope.Signatures) {
			t.Errorf("claim %s: the cursor-following peer has %d signature(s), the full-read peer %d",
				rec.ClaimID, len(got.Envelope.Signatures), len(want.Envelope.Signatures))
		}
	}
}
