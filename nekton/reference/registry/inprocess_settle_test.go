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

// TestDeferredBookkeepingIsIdempotent: a deferred claim is not in `r.seen` - it never reached the
// index - so `Add`'s twin path never catches a re-add, and the deferred branch counted it again
// every time. Adding one claim twice gave Deferred()=2 and Unresolved()=2 for a single record,
// appended a SECOND feed entry so Records(cursor) delivered it twice, and left both counters stuck
// above zero once it resolved: `head` then reports a truncation that is not there, and export's
// `deferred` count is wrong. Only a reopen cleared it - which the linked consumer this exists to
// serve does not do.
func TestDeferredBookkeepingIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedEnv, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	scoped, scopedID, err := claim.SignWith(claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID}, priv)
	if err != nil {
		t.Fatal(err)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(scoped); err != nil {
		t.Fatal(err)
	}
	_, isNew, err := r.Add(scoped) // the SAME deferred claim again
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("re-adding a deferred claim reported it as new")
	}
	if n := r.Deferred(); n != 1 {
		t.Errorf("Deferred() = %d after adding one claim twice, want 1", n)
	}
	if n := r.Unresolved(seedID); n != 1 {
		t.Errorf("Unresolved() = %d after adding one claim twice, want 1", n)
	}
	count := 0
	for _, rec := range r.Records(0) {
		if rec.ClaimID == scopedID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the feed carries the claim %d times - a peer's cursor would deliver it twice", count)
	}

	if _, _, err := r.Add(seedEnv); err != nil {
		t.Fatal(err)
	}
	if n := r.Deferred(); n != 0 {
		t.Errorf("Deferred() = %d once everything resolved, want 0 - export would carry that count", n)
	}
	if n := r.Unresolved(seedID); n != 0 {
		t.Errorf("Unresolved() = %d once everything resolved, want 0 - `head` would report a "+
			"truncation that is not there", n)
	}
}

// TestACoSignatureOnADeferredClaimSurvives: the idempotence guard added for the double-count bug
// returned unconditionally on a re-add, which DISCARDED the merged envelope. A co-signature on a
// deferred claim reached disk - persistClaim had already unioned it - but not the live record and
// not the feed, so a syncing peer never received the second signature and the claim was later
// indexed carrying one. Only a reopen recovered it.
//
// That is signature loss, the one class this release's known-limitation note is about. The indexed
// twin path refreshes the record and appends the new envelope for exactly this reason; the deferred
// path must do the same, while still counting one deferred record.
func TestACoSignatureOnADeferredClaimSurvives(t *testing.T) {
	dir := t.TempDir()
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, privA)
	if err != nil {
		t.Fatal(err)
	}
	spec := claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID,
	}
	byA, idA, err := claim.SignWith(spec, privA)
	if err != nil {
		t.Fatal(err)
	}
	byB, idB, err := claim.SignWith(spec, privB)
	if err != nil {
		t.Fatal(err)
	}
	if idA != idB {
		t.Fatalf("the two signings produced different ids (%s, %s) - they must be one claim", idA, idB)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(byA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(byB); err != nil {
		t.Fatal(err)
	}

	rec, _, ok := r.DeferredClaim(idA)
	if !ok {
		t.Fatal("the claim is not deferred - the premise is gone")
	}
	if n := len(rec.Envelope.Signatures); n != 2 {
		t.Errorf("the live deferred record carries %d signatures, want 2 - the co-signature reached "+
			"disk but not the record", n)
	}
	// A peer must receive it: the feed carries the co-signature as its own line.
	sigs := 0
	for _, fr := range r.Records(0) {
		if fr.ClaimID == idA {
			if len(fr.Envelope.Signatures) > sigs {
				sigs = len(fr.Envelope.Signatures)
			}
		}
	}
	if sigs != 2 {
		t.Errorf("the feed offers at most %d signatures for this claim, want 2 - a syncing peer "+
			"never receives the second signer's evidence", sigs)
	}
	// Still ONE deferred record: the fix must not undo the double-count it replaced.
	if n := r.Deferred(); n != 1 {
		t.Errorf("Deferred() = %d, want 1", n)
	}
	if n := r.Unresolved(seedID); n != 1 {
		t.Errorf("Unresolved() = %d, want 1", n)
	}
}

// TestDeferredCountsSurviveAReopen: the double-count fix was applied to Add and NOT to settle, so it
// reproduced on every REPLAY - a co-signed deferred claim has one subnekton line per signature set,
// and settle counted each of them. The existing idempotence test misses this because it re-adds an
// identical envelope and never reopens; this one does both.
func TestDeferredCountsSurviveAReopen(t *testing.T) {
	dir := t.TempDir()
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedEnv, seedID, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, privA)
	if err != nil {
		t.Fatal(err)
	}
	spec := claim.Spec{
		Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID,
	}
	byA, id, err := claim.SignWith(spec, privA)
	if err != nil {
		t.Fatal(err)
	}
	byB, _, err := claim.SignWith(spec, privB)
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.Add(byA)
	r.Add(byB)

	// REOPEN: settle replays both lines.
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := r2.Deferred(); n != 1 {
		t.Errorf("after reopen Deferred() = %d for ONE claim, want 1", n)
	}
	if n := r2.Unresolved(seedID); n != 1 {
		t.Errorf("after reopen Unresolved() = %d for ONE claim, want 1 - `head` would report a "+
			"truncation that is not there", n)
	}
	// The FEED legitimately carries one line per signature set - `a co-signature is its OWN line, so
	// it has its own position and is delivered like anything else; the reader unions lines that share
	// a claim id`. So the assertion is not "one line"; it is that a peer can reconstruct BOTH
	// signatures from what is offered. (My first version of this test asserted one line and failed,
	// and the design comment above the feed field is what settled which of the two was wrong.)
	union := map[string]bool{}
	for _, fr := range r2.Records(0) {
		if fr.ClaimID != id {
			continue
		}
		for _, sg := range fr.Envelope.Signatures {
			union[sg.KeyID] = true
		}
	}
	if len(union) != 2 {
		t.Errorf("the feed offers %d distinct signers for this claim after reopen, want 2 - a peer "+
			"must be able to union both", len(union))
	}
	// And the counters return to zero once it resolves.
	if _, _, err := r2.Add(seedEnv); err != nil {
		t.Fatal(err)
	}
	if n := r2.Deferred(); n != 0 {
		t.Errorf("Deferred() = %d after the seed arrived, want 0", n)
	}
	if n := r2.Unresolved(seedID); n != 0 {
		t.Errorf("Unresolved() = %d after the seed arrived, want 0", n)
	}
}
