package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

// kton-review's findings on #259, one test each, built as the review reproduced them.

func keyOf(s string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(s))
	return ed25519.NewKeyFromSeed(h[:])
}

func note(s string) claim.Spec {
	return claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:" + s}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}
}

// R1: an entry that arrives by Add - signed by a foreign key, naming this store's root and head - does
// not move the head, and the next own write continues from the store's own entry.
func TestReviewR1ForeignEntryDoesNotMoveHead(t *testing.T) {
	r, _ := Open(t.TempDir())
	own, err := r.Write(note("own"), keyOf("a"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:m"}}, Predicate: "https://kton.dev/v/x",
		By: "m", When: "2026-11-18T00:00:00Z", Scope: r.Root(), Prev: r.RootHead()}, keyOf("m"))
	if err != nil {
		t.Fatal(err)
	}
	fid, _, err := r.Add(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if r.RootHead() != own.ID {
		t.Fatalf("head moved to %s (foreign %s), want own %s", r.RootHead(), fid, own.ID)
	}
	next, err := r.Write(note("next"), keyOf("a"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := r.Claim(next.ID)
	st, _, _ := claim.ParseEnvelope(rec.Envelope)
	if p, _ := st.ParsePredicate(); p.Prev != own.ID {
		t.Errorf("next own write chains from %s, want %s", p.Prev, own.ID)
	}
	if off := r.OffChain(); len(off) != 1 || off[0] != fid {
		t.Errorf("OffChain = %v, want the foreign entry", off)
	}
}

// R2: one key, one second, two stores: two different roots.
func TestReviewR2RootsDoNotCollide(t *testing.T) {
	a, _ := Open(t.TempDir())
	b, _ := Open(t.TempDir())
	ra, err := a.CreateRoot(keyOf("a"), "b", "2026-11-18T00:00:00Z", "")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.CreateRoot(keyOf("a"), "b", "2026-11-18T00:00:00Z", "")
	if err != nil {
		t.Fatal(err)
	}
	if ra == rb {
		t.Fatalf("two stores got the same root %s", ra)
	}
	// a pinned name is reproducible, which is what --name is for
	c, _ := Open(t.TempDir())
	d, _ := Open(t.TempDir())
	rc, _ := c.CreateRoot(keyOf("a"), "b", "2026-11-18T00:00:00Z", "root/corpus")
	rd, _ := d.CreateRoot(keyOf("a"), "b", "2026-11-18T00:00:00Z", "root/corpus")
	if rc != rd {
		t.Errorf("pinned name and when should give the same root: %s %s", rc, rd)
	}
}

// R3: a registers entry anyone files under the root is not this store's registration.
func TestReviewR3ForeignRegistersIsNotCounted(t *testing.T) {
	r, _ := Open(t.TempDir())
	if _, err := r.Write(note("own"), keyOf("a")); err != nil {
		t.Fatal(err)
	}
	reg, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{Hash: "sha256:" + strings.Repeat("0", 63) + "7"}},
		Predicate: RegistersPredicate, By: "m", When: "2026-11-18T00:00:00Z", Scope: r.Root(), Prev: r.RootHead()}, keyOf("m"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(reg); err != nil {
		t.Fatal(err)
	}
	if n := len(r.Registered()); n != 0 {
		t.Errorf("Registered counts %d foreign registration(s)", n)
	}
	if n := len(r.Chain()); n != 1 {
		t.Errorf("Chain = %d entries, want this store's one", n)
	}
}

// R4: adopting a root that is already forked is refused unless the caller names the branch.
func TestReviewR4SetRootOnForkedClone(t *testing.T) {
	src, _ := Open(t.TempDir())
	root, err := src.CreateRoot(keyOf("a"), "b", "2026-11-18T00:00:00Z", "root/x")
	if err != nil {
		t.Fatal(err)
	}
	var heads []string
	for _, s := range []string{"one", "two"} {
		spec := note(s)
		spec.Scope, spec.Prev = root, root
		env, id, err := claim.SignWith(spec, keyOf("a"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := src.Add(env); err != nil {
			t.Fatal(err)
		}
		heads = append(heads, id)
	}
	dst, _ := Open(t.TempDir())
	for _, rec := range src.RawRecords() {
		if _, _, err := dst.Add(rec.Envelope); err != nil {
			t.Fatal(err)
		}
	}
	if err := dst.SetRoot(root, ""); err == nil || !strings.Contains(err.Error(), "forked") {
		t.Fatalf("SetRoot on a forked root: %v, want a refusal naming the heads", err)
	}
	if err := dst.SetRoot(root, heads[1]); err != nil {
		t.Fatal(err)
	}
	w, err := dst.Write(note("three"), keyOf("a"))
	if err != nil {
		t.Fatal(err)
	}
	if f := dst.Forks(root); len(f[root]) != 2 {
		t.Errorf("forks after continuing from a named head: %v (a third branch was opened)", f)
	}
	_ = w
}
