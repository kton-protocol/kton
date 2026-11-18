package registry

import (
	"fmt"
	"testing"
	"time"

	"kton.dev/nekton/claim"
)

// One write into a store holding n claims in another scope: write registry vs full Open (#248).
func TestLazyWriteCost(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	priv := lazyKey()
	dir := t.TempDir()
	r, _ := Open(dir)
	seed, err := r.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:nekton:scope:big"}}, PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "big", "genesis": true, "by": "b", "when": "2026-11-18T00:00:00Z", "parent": map[string]any{"uri": "urn:none"}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	prev := seed.ID
	const n = 5000
	for i := 0; i < n; i++ {
		w, err := r.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: fmt.Sprint("urn:b", i)}}, Predicate: "https://kton.dev/v/x", By: "b",
			When: "2026-11-18T00:00:00Z", Scope: seed.ID, Prev: prev}, priv)
		if err != nil {
			t.Fatal(err)
		}
		prev = w.ID
	}
	spec := func(i int) claim.Spec {
		return claim.Spec{Subject: []claim.SubjectSpec{{URI: fmt.Sprint("urn:w", i)}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}
	}
	t0 := time.Now()
	if _, err := WriteTo(dir, spec(1), priv); err != nil {
		t.Fatal(err)
	}
	lazy := time.Since(t0)
	t0 = time.Now()
	full, _ := Open(dir)
	if _, err := full.Write(spec(2), priv); err != nil {
		t.Fatal(err)
	}
	t.Logf("one write beside %d claims: write registry %v, full Open %v", n, lazy, time.Since(t0))
}
