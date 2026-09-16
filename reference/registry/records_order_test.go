package registry_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// SPEC §12 answers sync(since) with "records with a local sequence above `since`, IN APPEND ORDER".
// r.records holds whatever order the store was walked in - after a reopen that is object-filename
// order, which is hash order and has nothing to do with when anything was appended. A consumer that
// checkpoints incrementally reads a batch in order and keeps the last seq it saw; handed a
// descending batch it either mis-checkpoints or has to re-sort a promise it was already given.
func TestRecordsAreReturnedInSeqOrder(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x4c
	}
	priv := ed25519.NewKeyFromSeed(seed)

	add := func(r *registry.Registry, n int) {
		t.Helper()
		spec := foton.Spec{
			Inputs:   []foton.FileSpec{{Path: "in", Hash: core.HashBytes([]byte(strings.Repeat("x", n)))}},
			Outputs:  []foton.FileSpec{{Path: "out", Hash: core.HashBytes([]byte(strings.Repeat("y", n)))}},
			Protocol: &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"n": float64(n)}},
		}
		env, _, err := foton.SignWith(spec, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Ten records, so at least one ordering other than append order is overwhelmingly likely once
	// the store is re-walked by filename.
	for n := 1; n <= 10; n++ {
		add(r, n)
	}

	check := func(what string, recs []registry.Record, above int) {
		t.Helper()
		last := above
		for i, rec := range recs {
			if rec.Seq <= last {
				t.Errorf("%s: record %d has seq %d, not above the previous %d - §12 promises append order",
					what, i, rec.Seq, last)
			}
			last = rec.Seq
		}
	}
	check("fresh", r.Records(0), 0)

	// The case that actually broke it: reopen, so the slice is rebuilt in object-filename order.
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := r2.Records(0)
	if len(all) != 10 {
		t.Fatalf("after reopen: %d records, want 10", len(all))
	}
	check("after reopen", all, 0)

	// And with a non-zero cursor, which is how a peer actually calls it.
	mid := all[4].Seq
	batch := r2.Records(mid)
	if len(batch) == 0 {
		t.Fatal("since-cursor returned nothing")
	}
	check("since cursor", batch, mid)
}
