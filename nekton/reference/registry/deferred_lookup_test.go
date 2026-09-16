package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

// A scoped claim whose seed has not arrived is PERSISTED and offered to peers, but kept out of every
// index - deliberately. What was missing is the ability to LOOK IT UP: `Claim(id)` answered exactly
// as it does for a hash nobody ever heard of, so held-but-deferred collapsed into not-held. SPEC §12
// makes that distinction normative ("we do not have it" and "we have nothing about it" are different
// answers), and held-but-waiting is a third state the kernel already knew about - it is in `feed` and
// counted by `Deferred()`.
//
// This test walks all three, then adds the seed and checks the claim becomes ordinary.
func TestDeferredClaimIsDistinguishableFromNotHeld(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A seed authored but NOT added: its scope id exists, this store does not hold it. Built the
	// way `nekton seed` builds one (SPEC §7.4: genesis, no prev).
	seedEnv, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{
			"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z",
		},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	scopedEnv, scopedID, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:x"}},
		Predicate: "https://kton.dev/v/note",
		Object:    map[string]any{"a": "1"},
		By:        "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	r, err := registry.Open(filepath.Join(dir, "reg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(scopedEnv); err != nil {
		t.Fatalf("a scoped claim whose seed is missing must be PERSISTED, not refused (SPEC §11): %v", err)
	}

	// 1. not held at all
	unknown := "sha256:" + "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00"
	if _, ok := r.Claim(unknown); ok {
		t.Fatal("an unknown id resolved")
	}
	if _, _, ok := r.DeferredClaim(unknown); ok {
		t.Fatal("an unknown id was reported as deferred")
	}

	// 2. held and DEFERRED - the state that used to be invisible
	if _, ok := r.Claim(scopedID); ok {
		t.Error("a deferred claim answered the index lookup - it must not appear in about/by either")
	}
	rec, waiting, ok := r.DeferredClaim(scopedID)
	if !ok {
		t.Fatal("the deferred claim cannot be looked up, so it is indistinguishable from an unknown id")
	}
	if waiting != seedID {
		t.Errorf("waiting on %q, want the scope it names (%s)", waiting, seedID)
	}
	if rec.Envelope.Payload != scopedEnv.Payload {
		t.Error("the deferred lookup returned a different record")
	}
	if n := r.Deferred(); n != 1 {
		t.Errorf("Deferred() = %d, want 1", n)
	}

	// It survives a reopen as the same fact: a claim deferred at ingest and one deferred on replay
	// are the same state, and a reader must not get a different answer before and after a restart.
	r2, err := registry.Open(filepath.Join(dir, "reg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r2.DeferredClaim(scopedID); !ok {
		t.Error("after reopen the deferred claim is invisible again - settle's deferral path does not record it")
	}

	// 3. add the seed: the claim becomes ordinary, and stops being deferred.
	if _, _, err := r2.Add(seedEnv); err != nil {
		t.Fatalf("adding the seed: %v", err)
	}
	r3, err := registry.Open(filepath.Join(dir, "reg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r3.Claim(scopedID); !ok {
		t.Fatal("the claim did not resolve once its seed arrived - deferral is supposed to be temporary")
	}
	if _, _, ok := r3.DeferredClaim(scopedID); ok {
		t.Error("the claim is indexed AND still reported as deferred - two answers about one record")
	}
	if n := r3.Deferred(); n != 0 {
		t.Errorf("Deferred() = %d after the seed arrived, want 0", n)
	}
}
