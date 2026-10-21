package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

// A claim file planted under a dot name, as a git merge can bring it, is read by Open, so it moves the
// position too (review of #234, P1).
func TestPositionFollowsWhatOpenReads(t *testing.T) {
	sign := func(dir, what string) {
		t.Helper()
		s := sha256.Sum256([]byte(what))
		env, _, err := claim.SignWith(claim.Spec{
			Subject: []claim.SubjectSpec{{Hash: "sha256:" + strings.Repeat("a", 64)}}, Predicate: "https://kton.dev/v/" + what,
			By: "k", When: "2026-10-21T00:00:00Z",
		}, ed25519.NewKeyFromSeed(s[:]))
		if err != nil {
			t.Fatal(err)
		}
		r, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
	}
	dir, other := t.TempDir(), t.TempDir()
	sign(dir, "one")
	sign(other, "two")
	before, _ := ReadPosition(dir)
	n := len(mustOpen(t, dir).Records(0))

	b, err := os.ReadFile(filepath.Join(other, "objects", "unscoped.nekton.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "objects", ".h", "x.nekton.jsonl")
	os.MkdirAll(filepath.Dir(planted), 0o755)
	os.WriteFile(planted, b, 0o644)
	if len(mustOpen(t, dir).Records(0)) == n {
		t.Skip("Open does not read a claim file under a dot directory here; nothing for the position to see")
	}
	if after, _ := ReadPosition(dir); after.Objects == before.Objects {
		t.Error("Open reads the planted claim, the position did not change")
	}
}

func mustOpen(t *testing.T, dir string) *Registry {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
