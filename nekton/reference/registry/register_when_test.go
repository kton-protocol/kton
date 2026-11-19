package registry

import (
	"fmt"
	"testing"

	"kton.dev/nekton/claim"
)

// A seed's registration entry carries the seed's own time, not the wall clock: a store with a pinned
// root that writes the same seed with a fixed --when rebuilds to the same root chain (kton-web and
// kton-review, 19.11.; kton-examples 05-review-scope churned on every run).
func TestRegistrationCarriesTheSeedsWhen(t *testing.T) {
	calls := 0
	defer func(f func() string) { now = f }(now)
	now = func() string { calls++; return fmt.Sprintf("2099-01-01T00:00:%02dZ", calls) }

	build := func() (root string, chain []string) {
		r, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateRoot(keyOf("a"), "b", "2026-11-19T00:00:00Z", "lab-root"); err != nil {
			t.Fatal(err)
		}
		seed := claim.Spec{
			Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:lab"}},
			PredicateType: claim.ScopePredicateType,
			PredicateBody: map[string]any{"scope": "lab", "genesis": true, "by": "b", "when": "2026-11-19T01:00:00Z"},
		}
		w, err := r.Write(seed, keyOf("a"))
		if err != nil {
			t.Fatal(err)
		}
		if w.Registered == "" {
			t.Fatal("the seed was not registered")
		}
		return r.Root(), r.Chain()
	}
	root1, chain1 := build()
	root2, chain2 := build()
	if root1 != root2 || fmt.Sprint(chain1) != fmt.Sprint(chain2) {
		t.Fatalf("same root, key and --when gave different chains:\n%s %v\n%s %v", root1, chain1, root2, chain2)
	}
	if calls != 0 {
		t.Errorf("the wall clock was read %d time(s) for a seed with its own when", calls)
	}
}
