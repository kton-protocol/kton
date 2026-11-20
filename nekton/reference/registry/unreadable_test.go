package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kton-review F2 (via kton-cockpit): a store line that does not parse is skipped with a warning, and
// is in neither the index, RawRecords nor Dropped. Unreadable counts it, on every read path, so a
// reader that needs the whole store can refuse one that is not.
func TestUnreadableCountsALineThatDoesNotParse(t *testing.T) {
	dir := t.TempDir()
	r, _ := Open(dir)
	w, err := r.Write(note("a"), keyOf("a"))
	if err != nil {
		t.Fatal(err)
	}
	if n := r.Unreadable(); n != 0 {
		t.Fatalf("a whole store: Unreadable = %d, want 0", n)
	}
	// Half a line in the root's scope file, then a whole line after it (as a later append leaves it).
	var scopeFile string
	filepath.Walk(filepath.Join(dir, "objects"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".nekton.jsonl") {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), w.ID) {
				scopeFile = p
			}
		}
		return nil
	})
	if scopeFile == "" {
		t.Fatal("no scope file holds the written claim")
	}
	fh, err := os.OpenFile(scopeFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(`{"claimId":"sha256:half` + "\n")
	fh.Close()

	full, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := full.Unreadable(); n != 1 {
		t.Errorf("Open: Unreadable = %d, want 1", n)
	}
	if n := len(full.RawRecords()); n != 2 {
		t.Errorf("RawRecords = %d, want the root and the claim", n)
	}
	if full.Dropped() != 0 {
		t.Errorf("Dropped = %d: an unreadable line is not a dropped record", full.Dropped())
	}

	u, err := OpenUnion(t.TempDir(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := u.Unreadable(); n != 1 {
		t.Errorf("OpenUnion: Unreadable = %d, want 1 (a line lost in any source)", n)
	}

	lazy, err := OpenForWrite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lazy.Write(note("b"), keyOf("a")); err != nil {
		t.Fatal(err)
	}
	if n := lazy.Unreadable(); n != 1 {
		t.Errorf("OpenForWrite after loading the scope: Unreadable = %d, want 1", n)
	}
}
