package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// TestAddResolvesWhatWasWaiting: a record deferred for a missing dependency used to stay deferred
// for the life of the process, even after that dependency was added:
//
//	add the scoped claim    -> indexed=false deferred=true
//	add its seed            -> indexed=false deferred=true   <- still
//	reopen                  -> indexed=true  deferred=false
//
// The CLI hid it, because the next command reopens. A LINKED consumer - which is what the registry
// methods and the template package were extracted for this release - saw a claim that never
// resolved, with no way to tell that reopening would fix it. So every assertion here is at the
// LIBRARY level, with no Open in between.
func TestAddResolvesWhatWasWaiting(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(subject, prev, scope string) (core.Envelope, string) {
		t.Helper()
		env, id, err := claim.SignWith(claim.Spec{
			Subject: []claim.SubjectSpec{{URI: subject}}, Predicate: "https://kton.dev/v/note",
			Object: map[string]any{"s": subject}, By: "CN=t", When: "2026-07-16T00:00:00Z",
			Scope: scope, Prev: prev}, priv)
		if err != nil {
			t.Fatal(err)
		}
		return env, id
	}
	seedEnv, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	link, linkID := sign("urn:a", seedID, seedID)
	// A second link on top of the first: one arrival must unblock a CHAIN, not only the record that
	// names the newcomer directly.
	tip, tipID := sign("urn:b", linkID, seedID)

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The worst order: tip, then link, then the seed they both depend on.
	for _, env := range []core.Envelope{tip, link} {
		if _, _, err := r.Add(env); err != nil {
			t.Fatalf("a claim whose dependency is missing must be PERSISTED, not refused (SPEC §11): %v", err)
		}
	}
	if r.Deferred() != 2 {
		t.Fatalf("Deferred() = %d, want 2 - the premise is gone", r.Deferred())
	}

	if _, _, err := r.Add(seedEnv); err != nil {
		t.Fatalf("adding the seed: %v", err)
	}

	// No reopen. This is the whole point.
	for _, id := range []string{seedID, linkID, tipID} {
		if _, ok := r.Claim(id); !ok {
			t.Errorf("claim %s did not resolve in the same process after its dependency arrived", id)
		}
		if _, _, ok := r.DeferredClaim(id); ok {
			t.Errorf("claim %s is indexed AND still reported deferred - two answers about one record", id)
		}
	}
	if n := r.Deferred(); n != 0 {
		t.Errorf("Deferred() = %d after everything resolved, want 0", n)
	}
	if n := r.Unresolved(seedID); n != 0 {
		t.Errorf("Unresolved(scope) = %d after everything resolved, want 0 - `head` would report a "+
			"truncation that is not there", n)
	}

	// The feed must not have grown a second entry for a record it already offered: it was delivered
	// when it arrived, and delivering it twice makes a peer's cursor see the same claim again.
	seen := map[string]int{}
	for _, rec := range r.Records(0) {
		seen[rec.ClaimID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("the feed carries claim %s %d times; settling must not re-append", id, n)
		}
	}

	// And it really is on disk that way, not only in memory.
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Len() != 3 || r2.Deferred() != 0 {
		t.Errorf("after reopen: Len=%d Deferred()=%d, want 3 and 0", r2.Len(), r2.Deferred())
	}
}

// A record whose dependency never arrives must STAY deferred - settling must not quietly promote
// something unresolved, which would be the opposite failure and a worse one.
func TestSettlingDoesNotPromoteAnUnresolvedRecord(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	orphan, orphanID, err := claim.SignWith(claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID}, priv)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, _, err := claim.SignWith(claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:unrelated"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "2"}, By: "CN=t", When: "2026-07-16T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(orphan); err != nil {
		t.Fatal(err)
	}
	// Adding something unrelated triggers a settle pass; the orphan's seed is still missing.
	if _, _, err := r.Add(unrelated); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Claim(orphanID); ok {
		t.Error("a record whose seed never arrived was promoted into the index")
	}
	if _, _, ok := r.DeferredClaim(orphanID); !ok {
		t.Error("the record stopped being deferred without resolving - it is now in neither state")
	}
	if n := r.Deferred(); n != 1 {
		t.Errorf("Deferred() = %d, want 1", n)
	}
}
