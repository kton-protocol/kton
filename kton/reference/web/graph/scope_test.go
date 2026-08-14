package main

// The properties that matter for the §7.4 chain read in the browser:
//
//   - it agrees with the native kernel about what the heads of a scope are (a page and `nekton head`
//     must not disagree about a scope's tips), and
//   - it keeps the two failure modes apart that §7.4 insists are different: an UNRESOLVED prev is a
//     resolution fact another source may repair, a MALFORMED claim never is. Collapsing them is the
//     mistake that turns a monotone substrate into one that rejects on incompleteness.

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"kton.dev/nekton/claim"
)

// scopeKey returns a deterministic signer so a failure reproduces.
func scopeKey(t *testing.T, n byte) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n
	}
	return ed25519.NewKeyFromSeed(seed)
}

// seedScope authors a scope seed and returns its id plus the union record for it.
func seedScope(t *testing.T, priv ed25519.PrivateKey) (string, record) {
	t.Helper()
	spec := claim.Spec{
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "test-scope", "responsible": []any{"tester"}, "genesis": true},
	}
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return id, record{ClaimID: id, Envelope: env}
}

// link authors a scoped claim chaining onto prev.
func link(t *testing.T, priv ed25519.PrivateKey, scope, prev, when string) (string, record) {
	t.Helper()
	spec := claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:note:" + when}},
		Predicate: "https://kton.dev/v/note",
		By:        "tester",
		When:      when,
		Scope:     scope,
		Prev:      prev,
	}
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	return id, record{ClaimID: id, Envelope: env}
}

func buildScope(t *testing.T, recs []record, scope string) scopeView {
	t.Helper()
	b, err := json.Marshal(recs)
	if err != nil {
		t.Fatalf("marshal union: %v", err)
	}
	out, err := BuildScope(string(b), scope)
	if err != nil {
		t.Fatalf("BuildScope: %v", err)
	}
	var v scopeView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("unmarshal view: %v", err)
	}
	return v
}

func TestLinearChainIsOrderedAndSealable(t *testing.T) {
	priv := scopeKey(t, 1)
	scope, seedRec := seedScope(t, priv)
	id1, r1 := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")
	id2, r2 := link(t, priv, scope, id1, "2026-08-13T11:00:00Z")

	// Deliberately out of order in the union: order is a property of the chain, not of arrival.
	v := buildScope(t, []record{r2, seedRec, r1}, scope)

	if !v.SeedPresent || v.ChainLen != 2 {
		t.Fatalf("seedPresent=%v chainLen=%d, want true/2", v.SeedPresent, v.ChainLen)
	}
	if len(v.Heads) != 1 || v.Heads[0].ID != id2 {
		t.Fatalf("heads = %+v, want the single head %s", v.Heads, id2)
	}
	want := []string{scope, id1, id2}
	if got := v.Heads[0].Path; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("path = %v, want seed-first %v", got, want)
	}
	if !v.Verdict.Sealable || v.Verdict.Branched {
		t.Fatalf("verdict = %+v, want sealable and unbranched", v.Verdict)
	}
	if v.Members[0].Depth != 1 || v.Members[1].Depth != 2 {
		t.Fatalf("depths = %d,%d, want 1,2 (the seed sits at 0)", v.Members[0].Depth, v.Members[1].Depth)
	}
}

// A fork is a legal state: two writers appended to the head each last saw, then synced.
func TestBranchedScopeReportsBothHeadsAndStaysSealable(t *testing.T) {
	priv := scopeKey(t, 2)
	scope, seedRec := seedScope(t, priv)
	idA, rA := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")
	idB, rB := link(t, priv, scope, scope, "2026-08-13T10:05:00Z")

	v := buildScope(t, []record{seedRec, rA, rB}, scope)

	if len(v.Heads) != 2 {
		t.Fatalf("heads = %+v, want 2", v.Heads)
	}
	if !v.Verdict.Branched || !v.Verdict.Sealable {
		t.Fatalf("verdict = %+v, want branched AND sealable: both branches reach the seed", v.Verdict)
	}
	// Each head commits to its own path and nothing on the sibling branch - the mechanical fact the
	// CLI hint states, now checkable.
	for _, h := range v.Heads {
		if len(h.Path) != 2 || h.Path[0] != scope {
			t.Fatalf("head %s path = %v, want [seed, itself]", h.ID, h.Path)
		}
		if h.Path[1] == idA && h.ID != idA {
			t.Fatalf("head %s carries the sibling branch's claim", h.ID)
		}
	}
	if v.Heads[0].ID != idA && v.Heads[0].ID != idB {
		t.Fatalf("unexpected head %s", v.Heads[0].ID)
	}
}

// The monotonicity case: withhold the middle link. The chain cannot reach the seed from what is
// here, and that MUST read as unresolved-so-far, not as an error and not as a defect.
func TestMissingPrevIsAGapNotAnError(t *testing.T) {
	priv := scopeKey(t, 3)
	scope, seedRec := seedScope(t, priv)
	id1, _ := link(t, priv, scope, scope, "2026-08-13T10:00:00Z") // deliberately NOT in the union
	id2, r2 := link(t, priv, scope, id1, "2026-08-13T11:00:00Z")

	v := buildScope(t, []record{seedRec, r2}, scope)

	if len(v.Heads) != 1 || v.Heads[0].ID != id2 {
		t.Fatalf("heads = %+v, want the orphan as the single head", v.Heads)
	}
	if v.Heads[0].ReachesSeed {
		t.Fatal("head reaches the seed, but the middle link was withheld")
	}
	if v.Heads[0].Gap != id1 {
		t.Fatalf("gap = %q, want the withheld link %s named exactly", v.Heads[0].Gap, id1)
	}
	if len(v.Defects) != 0 {
		t.Fatalf("defects = %+v, want none: a gap is a resolution fact, not a grammar violation", v.Defects)
	}
	if v.Verdict.Sealable {
		t.Fatal("verdict is sealable despite a gap")
	}

	// Monotonicity proper: supplying the missing record only ever ADDS. Same union plus one link,
	// and the same read now seals.
	_, r1 := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")
	v2 := buildScope(t, []record{seedRec, r2, r1}, scope)
	if !v2.Verdict.Sealable || len(v2.Heads) != 1 || v2.Heads[0].Gap != "" {
		t.Fatalf("after resolving the gap: verdict=%+v heads=%+v, want sealable and gapless", v2.Verdict, v2.Heads)
	}
}

// An absent seed is the other incomplete case: nothing can be judged, but nothing is invalid.
func TestAbsentSeedIsIncompleteNotInvalid(t *testing.T) {
	priv := scopeKey(t, 4)
	scope, _ := seedScope(t, priv) // the seed is NOT put in the union
	_, r1 := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")

	v := buildScope(t, []record{r1}, scope)

	if v.SeedPresent || v.Verdict.Sealable {
		t.Fatalf("view = %+v, want seed absent and not sealable", v.Verdict)
	}
	if v.ChainLen != 1 {
		t.Fatalf("chainLen = %d, want the member still counted", v.ChainLen)
	}
	if len(v.Defects) != 0 {
		t.Fatalf("defects = %+v, want none: an unresolved seed is not a grammar violation", v.Defects)
	}
}

// A defect is the case no further source can repair, and it must not be dressed up as a gap.
func TestMissingPrevFieldIsADefect(t *testing.T) {
	priv := scopeKey(t, 5)
	scope, seedRec := seedScope(t, priv)
	// scope set, prev omitted: forbidden by 7.4 on every non-genesis statement.
	spec := claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:note:nop"}},
		Predicate: "https://kton.dev/v/note",
		By:        "tester",
		When:      "2026-08-13T10:00:00Z",
		Scope:     scope,
	}
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	v := buildScope(t, []record{seedRec, {ClaimID: id, Envelope: env}}, scope)

	if len(v.Defects) != 1 || v.Defects[0].ID != id {
		t.Fatalf("defects = %+v, want exactly the prev-less claim", v.Defects)
	}
	if v.Verdict.Sealable {
		t.Fatal("verdict is sealable despite a grammar defect")
	}
}

// An opened but unwritten scope: the seed is its own tip. The CLI answers this way, and a page that
// answered differently would disagree with it on the very first screen a new scope shows.
func TestEmptyScopeHasTheSeedAsItsHead(t *testing.T) {
	priv := scopeKey(t, 6)
	scope, seedRec := seedScope(t, priv)

	v := buildScope(t, []record{seedRec}, scope)

	if v.ChainLen != 0 || len(v.Heads) != 1 || v.Heads[0].ID != scope {
		t.Fatalf("view = %+v, want the seed as the single head", v)
	}
	if !v.Verdict.Sealable || !v.Heads[0].ReachesSeed {
		t.Fatalf("verdict = %+v, want an empty scope to read as sealable", v.Verdict)
	}
}

// Records from another scope, and non-claim noise, must not leak into this scope's read.
func TestForeignRecordsAreIgnored(t *testing.T) {
	priv := scopeKey(t, 7)
	scope, seedRec := seedScope(t, priv)
	id1, r1 := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")

	other := scopeKey(t, 8)
	otherScope, otherSeed := seedScope(t, other)
	_, otherLink := link(t, other, otherScope, otherScope, "2026-08-13T10:00:00Z")

	v := buildScope(t, []record{seedRec, r1, otherSeed, otherLink}, scope)

	if v.ChainLen != 1 || len(v.Heads) != 1 || v.Heads[0].ID != id1 {
		t.Fatalf("view = %+v, want only this scope's single member", v)
	}
	if !v.Verdict.Sealable {
		t.Fatalf("verdict = %+v, want sealable", v.Verdict)
	}
}

// A planted record whose declared id names a real member must not be able to insert itself into the
// chain: the id is re-derived from the envelope, so the lie is simply not believed.
func TestDeclaredIDIsNotTrusted(t *testing.T) {
	priv := scopeKey(t, 9)
	scope, seedRec := seedScope(t, priv)
	id1, r1 := link(t, priv, scope, scope, "2026-08-13T10:00:00Z")

	// A different claim, shipped under id1's name.
	_, planted := link(t, priv, scope, scope, "2026-08-13T23:59:00Z")
	planted.ClaimID = id1

	v := buildScope(t, []record{seedRec, r1, planted}, scope)

	for _, m := range v.Members {
		if m.ID == id1 && m.When == "2026-08-13T23:59:00Z" {
			t.Fatal("the planted claim was indexed under the declared id it borrowed")
		}
	}
	if v.ChainLen != 2 {
		t.Fatalf("chainLen = %d, want both claims read under their OWN derived ids", v.ChainLen)
	}
}
