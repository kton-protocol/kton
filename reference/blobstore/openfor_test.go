package blobstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/blobstore"
)

// OpenFor replaces a filepath.Join every caller wrote by hand, against a constant that lived in the
// COCKPIT's federation package - plankton's own storage layout declared in a package that depends on
// plankton. Moving it is only safe if the path is unchanged: an existing store must stay readable,
// and `plankton pin` and `kton pin` must reach the same bytes. This pins the layout so a later
// refactor cannot quietly relocate everyone's pinned bytes.
func TestOpenForKeepsTheExistingLayout(t *testing.T) {
	reg := t.TempDir()

	s, err := blobstore.OpenFor(reg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Put([]byte("the bytes"))
	if err != nil {
		t.Fatal(err)
	}

	// The same directory a hand-built join produced, and the same one an already-pinned store has.
	if blobstore.Subdir != "blobs" {
		t.Fatalf("Subdir = %q; changing it orphans every store that already pinned bytes", blobstore.Subdir)
	}
	if _, err := os.Stat(filepath.Join(reg, "blobs")); err != nil {
		t.Fatalf("OpenFor did not create <registry>/blobs: %v", err)
	}

	// A store opened the old way sees exactly the same blob.
	old, err := blobstore.Open(filepath.Join(reg, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	if !old.Has(h) {
		t.Fatal("a blob pinned through OpenFor is invisible to a store opened at <registry>/blobs")
	}
}

// Reading re-hashes. `Has` alone only says a file exists, and a present-and-good status line that
// never verifies anything is the failure shape this substrate exists to prevent.
func TestAReadDetectsRot(t *testing.T) {
	reg := t.TempDir()
	s, err := blobstore.OpenFor(reg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Put([]byte("the bytes"))
	if err != nil {
		t.Fatal(err)
	}

	var blob string
	filepath.Walk(filepath.Join(reg, "blobs"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			blob = p
		}
		return nil
	})
	if blob == "" {
		t.Fatal("no blob file was written - nothing to rot")
	}
	if err := os.WriteFile(blob, []byte("something else entirely"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !s.Has(h) {
		t.Fatal("the file is still there; Has is expected to say so - that is why Get must re-hash")
	}
	if _, err := s.Get(h); err == nil {
		t.Fatal("a rotted blob read back clean: Get must re-hash and refuse")
	}
}
