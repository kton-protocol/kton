package main

import (
	"testing"

	"kton.dev/plankton/registry"
)

// TestFulfilmentPartial converts spec-test Scenario 7 (the Half-Passing Candidate): fulfilling a
// spectrum requires reproducing EVERY member; partial fulfilment is non-fulfilment. `fulfils` is the
// per-member reproducible predicate spectrum-check uses (identical / via-normalizer / not-fulfilled),
// so a candidate that reproduces only some members is not fully fulfilled.
func TestFulfilmentPartial(t *testing.T) {
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := fulfils(r, "sha256:aaa", "sha256:aaa", ""); got != "identical" {
		t.Fatalf("a matching candidate should be fulfilled, got %q", got)
	}
	if got := fulfils(r, "sha256:aaa", "sha256:bbb", ""); got != "" {
		t.Fatalf("a non-matching candidate must NOT be fulfilled, got %q", got)
	}

	// A two-member spectrum where the candidate reproduces only one member.
	members := map[string]string{"m1": "sha256:aaa", "m2": "sha256:ccc"}
	cand := map[string]string{"m1": "sha256:aaa", "m2": "sha256:zzz"} // m2 does not reproduce
	fulfilled := 0
	for name, ref := range members {
		if fulfils(r, ref, cand[name], "") != "" {
			fulfilled++
		}
	}
	if fulfilled == len(members) {
		t.Fatal("partial fulfilment must NOT count as fulfilling the spectrum")
	}
	if fulfilled != 1 {
		t.Fatalf("expected exactly 1/%d members fulfilled, got %d", len(members), fulfilled)
	}
}
