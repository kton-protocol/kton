package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// nekton's Held: the consumer keeps it from Records; a co-signature does not change it; a claim line
// removed from outside does (#260).
func TestHeldFollowsRecordsAndSeesRemovals(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec := func(what string) claim.Spec {
		return claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:" + what}}, Predicate: "https://kton.dev/v/x", By: "k", When: "2026-11-18T00:00:00Z"}
	}
	keyOf := func(s string) ed25519.PrivateKey { h := sha256.Sum256([]byte(s)); return ed25519.NewKeyFromSeed(h[:]) }
	var bID string
	for _, w := range []string{"a", "b", "c"} {
		env, _, err := claim.SignWith(spec(w), keyOf("one"))
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := r.Add(env)
		if err != nil {
			t.Fatal(err)
		}
		if w == "b" {
			bID = id
		}
	}
	mine, seen := "", map[string]bool{}
	for _, rec := range r.Records(0) {
		if k := HeldKey(rec); !seen[k] {
			seen[k] = true
			mine = core.HeldWith(mine, k)
		}
	}
	if p, _ := ReadPosition(dir); p.Held != mine {
		t.Fatalf("Held %s, the consumer's own %s", p.Held, mine)
	}
	co, _, err := claim.SignWith(spec("a"), keyOf("two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(co); err != nil {
		t.Fatal(err)
	}
	if p, _ := ReadPosition(dir); p.Held != mine {
		t.Errorf("a co-signature changed Held")
	}
	path := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// drop claim b's only line (a still has its co-signature line, so a is still held)
	var kept []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !strings.Contains(l, bID) {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, _ := ReadPosition(dir); p.Held == mine {
		t.Error("a removed claim line did not change Held")
	}
}

// A line that is not a record - a claimId with no envelope that hashes to it - does not count in Held
// (#261 review H1).
func TestHeldIgnoresNonRecords(t *testing.T) {
	dir := t.TempDir()
	r, _ := Open(dir)
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:a"}}, Predicate: "https://kton.dev/v/x", By: "k", When: "2026-11-18T00:00:00Z"}, ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	before, _ := ReadPosition(dir)
	f, err := os.OpenFile(filepath.Join(dir, "objects", "unscoped.nekton.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"claimId":"sha256:` + strings.Repeat("7", 64) + `"}` + "\n")
	f.Close()
	if after, _ := ReadPosition(dir); after.Held != before.Held {
		t.Error("a claimId-only line changed Held")
	}
}
