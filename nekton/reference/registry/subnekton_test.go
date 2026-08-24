package registry

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

func testKey(t *testing.T, seed byte) ed25519.PrivateKey {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func sign(t *testing.T, spec claim.Spec, priv ed25519.PrivateKey) (core.Envelope, string) {
	t.Helper()
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	return env, id
}

func seedSpec(name string) claim.Spec {
	return claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:" + name}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{
			"scope": name, "genesis": true, "by": "key:test", "when": "2026-08-24T00:00:00Z",
		},
	}
}

func chained(subject, scope, prev string) claim.Spec {
	return claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: subject}},
		Predicate: "https://example.org/v/reviewed",
		By:        "key:test", When: "2026-08-24T00:00:00Z",
		Scope: scope, Prev: prev,
	}
}

func bare(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func lines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return len(strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " \n")))
}

// A subnekton is ONE FILE: its seed and every claim chained under it, together. The unscoped nekton
// is one file too. That is the unit you can chmod, copy, or hand over.
func TestASubnektonIsOneFile(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	priv := testKey(t, 1)

	env, scopeID := sign(t, seedSpec("lab/studyA"), priv)
	if _, _, err := r.Add(env); err != nil {
		t.Fatalf("add seed: %v", err)
	}
	prev, ids := scopeID, []string{scopeID}
	for i, subj := range []string{"urn:demo:r1", "urn:demo:r2", "urn:demo:r3"} {
		env, id := sign(t, chained(subj, scopeID, prev), priv)
		if _, _, err := r.Add(env); err != nil {
			t.Fatalf("add c%d: %v", i+1, err)
		}
		prev, ids = id, append(ids, id)
	}
	env, loose := sign(t, claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:demo:loose"}},
		Predicate: "https://example.org/v/noted",
		By:        "key:test", When: "2026-08-24T00:00:00Z",
	}, priv)
	if _, _, err := r.Add(env); err != nil {
		t.Fatalf("add unscoped: %v", err)
	}

	sub := filepath.Join(dir, "objects", "scope", bare(scopeID)+".nekton.jsonl")
	unscoped := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")

	// The whole store is exactly two files: one subnekton, one unscoped nekton.
	var files []string
	filepath.Walk(filepath.Join(dir, "objects"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) != 2 {
		t.Errorf("store holds %d files, want 2 (one subnekton + the unscoped nekton): %v", len(files), files)
	}
	if n := lines(t, sub); n != 4 {
		t.Errorf("subnekton holds %d records, want 4 (seed + 3 chained)", n)
	}
	if n := lines(t, unscoped); n != 1 {
		t.Errorf("unscoped nekton holds %d records, want 1", n)
	}
	// Every claim of the scope is in that one file, and the loose one is not.
	body, _ := os.ReadFile(sub)
	for _, id := range ids {
		if !strings.Contains(string(body), id) {
			t.Errorf("claim %s missing from its subnekton file", id)
		}
	}
	if strings.Contains(string(body), loose) {
		t.Error("an unscoped claim was filed into a subnekton")
	}

	// Reopening rebuilds the same chain from the file: the file is a bag, `prev` is the order.
	r2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	heads, chainLen, ok := r2.Heads(scopeID)
	if !ok || chainLen != 3 || len(heads) != 1 || heads[0] != ids[3] {
		t.Errorf("after reopen: ok=%v chainLen=%d heads=%v, want the last claim as sole head", ok, chainLen, heads)
	}

	// Handing over the subnekton is copying one file.
	away := t.TempDir()
	if err := os.MkdirAll(filepath.Join(away, "objects", "scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(sub)
	if err := os.WriteFile(filepath.Join(away, "objects", "scope", filepath.Base(sub)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	r3, err := Open(away)
	if err != nil {
		t.Fatalf("open the handed-over subnekton: %v", err)
	}
	if _, n, ok := r3.Heads(scopeID); !ok || n != 3 {
		t.Errorf("a copied subnekton file did not resolve on its own: ok=%v chainLen=%d", ok, n)
	}
}

// Placement reads the SIGNED payload, so it never needs resolution: a claim whose seed has not
// arrived still lands in the right nekton while it waits (SPEC §11: incomplete, not invalid).
func TestDeferredClaimGoesToItsDeclaredSubnekton(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	absent := "sha256:" + strings.Repeat("ab", 32)
	env, id := sign(t, chained("urn:demo:orphan", absent, absent), testKey(t, 2))
	if _, isNew, err := r.Add(env); err != nil || !isNew {
		t.Fatalf("add deferred: isNew=%v err=%v (unresolved is persisted, not rejected)", isNew, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "objects", "scope", bare(absent)+".nekton.jsonl"))
	if err != nil || !strings.Contains(string(b), id) {
		t.Errorf("a claim naming an absent scope was not filed into that subnekton: %v", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len()=%d, want 0: a deferred claim is persisted but NOT indexed", r.Len())
	}
}

// Two independent co-signers of one statement are ONE record with TWO signatures - the union has to
// survive the file form (it is a rewrite of an existing line, not an append).
func TestCoSignatureUnionInsideASubnekton(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	priv1, priv2 := testKey(t, 3), testKey(t, 4)
	env, scopeID := sign(t, seedSpec("lab/cosign"), priv1)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	envA, idA := sign(t, chained("urn:demo:x", scopeID, scopeID), priv1)
	if _, _, err := r.Add(envA); err != nil {
		t.Fatal(err)
	}
	envB, idB := sign(t, chained("urn:demo:x", scopeID, scopeID), priv2)
	if idB != idA {
		t.Fatalf("twin id differs (%s != %s): the claim id must cover only the payload", idB, idA)
	}
	if _, _, err := r.Add(envB); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "objects", "scope", bare(scopeID)+".nekton.jsonl")
	if n := lines(t, sub); n != 2 {
		t.Errorf("subnekton holds %d records, want 2: a twin must MERGE, not add a rival line", n)
	}
	for _, of := range readSubnekton(sub) {
		if of.ClaimID == idA && len(of.Envelope.Signatures) != 2 {
			t.Errorf("record carries %d signature(s), want 2", len(of.Envelope.Signatures))
		}
	}
}

// A store an older build wrote is one file per claim. It must still load, and migrate into its
// subnekton the first time a write touches a record - without dropping a co-signature.
func TestLegacyPerClaimStoreLoadsAndMigrates(t *testing.T) {
	dir := t.TempDir()
	priv1, priv2 := testKey(t, 5), testKey(t, 6)
	envSeed, scopeID := sign(t, seedSpec("lab/legacy"), priv1)
	envC1, c1 := sign(t, chained("urn:demo:r1", scopeID, scopeID), priv1)

	flat := filepath.Join(dir, "objects", "sha256")
	if err := os.MkdirAll(flat, 0o755); err != nil {
		t.Fatal(err)
	}
	for id, env := range map[string]core.Envelope{scopeID: envSeed, c1: envC1} {
		b, err := json.MarshalIndent(objectFile{ClaimID: id, Envelope: env}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(flat, bare(id)+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on a legacy store: %v", err)
	}
	if _, n, ok := r.Heads(scopeID); !ok || n != 1 {
		t.Fatalf("legacy store did not load: ok=%v chainLen=%d", ok, n)
	}

	envTwin, _ := sign(t, chained("urn:demo:r1", scopeID, scopeID), priv2)
	if _, _, err := r.Add(envTwin); err != nil {
		t.Fatalf("add twin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(flat, bare(c1)+".json")); err == nil {
		t.Error("the legacy per-claim file survived migration, so the record now loads twice")
	}
	sub := filepath.Join(dir, "objects", "scope", bare(scopeID)+".nekton.jsonl")
	found := false
	for _, of := range readSubnekton(sub) {
		if of.ClaimID == c1 {
			found = true
			if len(of.Envelope.Signatures) != 2 {
				t.Errorf("migrated record carries %d signature(s), want 2: the union missed the legacy copy",
					len(of.Envelope.Signatures))
			}
		}
	}
	if !found {
		t.Error("the touched record did not migrate into its subnekton")
	}
}
