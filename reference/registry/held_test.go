package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	. "kton.dev/plankton/registry"
)

// Position.Held is what a consumer can keep current from Records alone: XOR in the key of every record
// Records(since) brings. A twin does not change it; a record removed from outside does (#260).
func TestHeldFollowsRecordsAndSeesRemovals(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range []string{"a", "b", "c"} {
		env, _ := signFoton(t, strings.Repeat(c, 64), nil)
		id, _, err := r.Add(env)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	mine, seen := "", map[string]bool{}
	for _, rec := range r.Records(0) {
		if k := HeldKey(rec); !seen[k] {
			seen[k] = true
			mine = core.HeldWith(mine, k)
		}
	}
	p, err := ReadPosition(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Held != mine {
		t.Fatalf("Held %s, the consumer's own %s", p.Held, mine)
	}
	twin, _ := signFoton(t, strings.Repeat("a", 64), []string{"https://example.org/out.csv"})
	if _, _, err := r.Add(twin); err != nil {
		t.Fatal(err)
	}
	if p2, _ := ReadPosition(dir); p2.Held != mine {
		t.Errorf("a twin changed Held")
	}
	_, h := splitKey(ids[1])
	if err := os.Remove(filepath.Join(dir, "objects", "sha256", h+".json")); err != nil {
		t.Fatal(err)
	}
	if p3, _ := ReadPosition(dir); p3.Held == mine {
		t.Error("a removed record did not change Held")
	}
}

func splitKey(k string) (string, string) {
	i := strings.IndexByte(k, ':')
	return k[:i], k[i+1:]
}

// A stray object file whose content does not derive its name does not count in Held (#261 review H1).
func TestHeldIgnoresStrayObjectFiles(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := signFoton(t, strings.Repeat("a", 64), nil)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	before, _ := ReadPosition(dir)
	stray := filepath.Join(dir, "objects", "sha256", strings.Repeat("9", 64)+".json")
	if err := os.WriteFile(stray, []byte(`{"note":"not a record"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if after, _ := ReadPosition(dir); after.Held != before.Held {
		t.Error("a stray object file changed Held")
	}
}
