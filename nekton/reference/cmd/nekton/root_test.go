package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func note(subject string) claimSpec {
	return claimSpec{
		Subject: []subjSpec{{URI: subject}}, Predicate: "https://kton.dev/v/reviewed",
		By: "CN=t", When: "2026-11-18T00:00:00Z",
	}
}

func predOf(t *testing.T, r *registry.Registry, id string) *claim.Predicate {
	t.Helper()
	rec, ok := r.Claim(id)
	if !ok {
		t.Fatalf("claim %s not held", id)
	}
	st, _, err := claim.ParseEnvelope(rec.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.ParsePredicate()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Claims written without a scope chain under the store's root, in order: each names the previous
// as prev, so the root is an ordered list, not a bag (#213).
func TestUnscopedWritesChainUnderRoot(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "reg")
	priv := newKey(t)
	for _, s := range []string{"urn:a", "urn:b", "urn:c"} {
		if err := signClaim(note(s), priv, "", true, reg, true); err != nil {
			t.Fatal(err)
		}
	}
	r, err := registry.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	root := r.Root()
	heads, n, ok := r.Heads(root)
	if !ok || n != 3 || len(heads) != 1 || heads[0] != r.RootHead() {
		t.Fatalf("root chain: ok %v, %d entries, heads %v, local head %s", ok, n, heads, r.RootHead())
	}
	// walk back from the head: three entries, then the root seed
	cur, steps := r.RootHead(), 0
	for cur != root {
		p := predOf(t, r, cur)
		if p.Scope != root {
			t.Fatalf("%s is not in the root scope", cur)
		}
		cur, steps = p.Prev, steps+1
	}
	if steps != 3 {
		t.Fatalf("walked %d entries back to the root, want 3", steps)
	}
	if len(r.Forks(root)) != 0 {
		t.Errorf("unexpected forks: %v", r.Forks(root))
	}
}

// init creates the root once; a second init is refused.
func TestInitCreatesTheRootOnce(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "reg")
	key := filepath.Join(t.TempDir(), "k")
	if err := keygen([]string{key}); err != nil {
		t.Fatal(err)
	}
	if err := initStore([]string{"--sign", key + ".key", "--registry", reg}); err != nil {
		t.Fatal(err)
	}
	r, _ := registry.Open(reg)
	if r.Root() == "" || !r.IsSeed(r.Root()) {
		t.Fatalf("no root after init: %q", r.Root())
	}
	if err := initStore([]string{"--sign", key + ".key", "--registry", reg}); err == nil {
		t.Error("a second init was accepted")
	}
}

// A new seed hangs off the root and is registered in the root chain.
func TestSeedIsRegisteredInTheRoot(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "reg")
	priv := newKey(t)
	spec := claimSpec{
		Subject:       []subjSpec{{URI: "urn:nekton:scope:study-1"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "study-1", "genesis": true, "by": "CN=t", "when": "2026-11-18T00:00:00Z"},
	}
	if err := signClaim(spec, priv, "", true, reg, true); err != nil {
		t.Fatal(err)
	}
	r, _ := registry.Open(reg)
	registered := r.Registered()
	if len(registered) != 1 {
		t.Fatalf("registered = %v, want the one seed", registered)
	}
	for child, held := range registered {
		if !held {
			t.Errorf("registered seed %s is not held", child)
		}
		p := predOf(t, r, child)
		if p.Parent == nil || p.Parent.Hash != r.Root() {
			t.Errorf("seed parent = %+v, want the root %s", p.Parent, r.Root())
		}
	}
}

// Two copies of one store that both keep writing fork the root. Both entries are kept and valid; the
// fork is reported, and an entry from the other copy does not move this store's head.
func TestRootForkIsReportedNotRejected(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	priv := newKey(t)
	if err := signClaim(note("urn:first"), priv, "", true, a, true); err != nil {
		t.Fatal(err)
	}
	ra, _ := registry.Open(a)
	// copy a into b as a clone would, including the root marker
	rb, err := registry.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range ra.RawRecords() {
		if _, _, err := rb.Add(rec.Envelope); err != nil {
			t.Fatal(err)
		}
	}
	if err := rb.SetRoot(ra.Root()); err != nil {
		t.Fatal(err)
	}
	headBefore := ra.RootHead()
	if err := signClaim(note("urn:in-a"), priv, "", true, a, true); err != nil {
		t.Fatal(err)
	}
	if err := signClaim(note("urn:in-b"), priv, "", true, b, true); err != nil {
		t.Fatal(err)
	}
	ra, _ = registry.Open(a)
	rb, _ = registry.Open(b)
	ownHead := ra.RootHead()
	for _, rec := range rb.RawRecords() { // mirror b into a
		if _, _, err := ra.Add(rec.Envelope); err != nil {
			t.Fatal(err)
		}
	}
	forks := ra.Forks(ra.Root())
	if len(forks[headBefore]) != 2 {
		t.Fatalf("forks = %v, want two entries continuing from %s", forks, headBefore)
	}
	if ra.RootHead() != ownHead {
		t.Errorf("a mirrored entry moved the local head from %s to %s", ownHead, ra.RootHead())
	}
}

// Ingesting signed envelopes never creates a root: a kernel does not sign on ingest.
func TestIngestCreatesNoRoot(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	priv := newKey(t)
	if err := signClaim(note("urn:x"), priv, "", true, src, true); err != nil {
		t.Fatal(err)
	}
	rs, _ := registry.Open(src)
	dst, err := registry.Open(filepath.Join(t.TempDir(), "dst"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range rs.RawRecords() {
		if _, _, err := dst.Add(rec.Envelope); err != nil {
			t.Fatal(err)
		}
	}
	if dst.Root() != "" {
		t.Errorf("ingest gave the store a root: %s", dst.Root())
	}
}

// nekton seed --parent X --add into a store without a root: stored and registered (root created).
func TestSeedWithParentIntoEmptyStore(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "reg")
	spec := claimSpec{
		Subject:       []subjSpec{{URI: "urn:nekton:scope:child"}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "child", "genesis": true, "by": "CN=t", "when": "2026-11-18T00:00:00Z", "parent": map[string]any{"uri": "urn:elsewhere"}},
	}
	if err := signClaim(spec, newKey(t), "", true, reg, true); err != nil {
		t.Fatal(err)
	}
	r, _ := registry.Open(reg)
	if r.Root() == "" || len(r.Registered()) != 1 {
		t.Fatalf("root %q, registered %v", r.Root(), r.Registered())
	}
}
