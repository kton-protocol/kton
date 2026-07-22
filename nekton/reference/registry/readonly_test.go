package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// A read (OpenUnion, and the mirror's peer-open) MUST NOT create objects/ in the source: a read-only
// peer would otherwise fail with permission-denied, and a writable peer would gain a stray directory.
// Open (the create path) still provisions the store.
func TestOpenUnionDoesNotMutateSource(t *testing.T) {
	dir := t.TempDir()

	if _, err := OpenUnion(dir); err != nil {
		t.Fatalf("OpenUnion: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "objects")); !os.IsNotExist(err) {
		t.Error("OpenUnion created objects/ in the source (a read must not mutate the source)")
	}

	if _, err := Open(dir); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "objects")); err != nil {
		t.Errorf("Open (create path) should provision objects/: %v", err)
	}

	// A named source that does not exist is an error, not a silently-empty registry.
	if _, err := OpenUnion(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("OpenUnion on a missing directory should error")
	}
}
