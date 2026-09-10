package core_test

import (
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/core"
)

// AUD-01. `os.WriteFile(path, seed, 0600)` loses a key in two ways, and both were live:
// the mode applies only to a NEW file, so an existing 0644 key file kept 0644 and took the new
// private seed; and `keygen alice` twice succeeded twice, destroying the only copy of the first
// seed. The signatures made with it stay valid - what is destroyed is the ability to check them.
func TestWriteKeyFileNeverOverwritesAnIdentity(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alice.key")

	if err := core.WriteKeyFile(p, []byte("first"), 0o600, false); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}

	t.Run("a different key is refused and the bytes are untouched", func(t *testing.T) {
		if err := core.WriteKeyFile(p, []byte("second"), 0o600, false); err == nil {
			t.Fatal("overwrote an existing identity")
		}
		if b, _ := os.ReadFile(p); string(b) != "first" {
			t.Fatalf("existing key was modified: %q", b)
		}
	})

	t.Run("the same key is idempotent", func(t *testing.T) {
		// A deterministic `--seed` re-run must not need --force: reproducible snapshots depend on
		// generating the same identity twice.
		if err := core.WriteKeyFile(p, []byte("first"), 0o600, false); err != nil {
			t.Fatalf("re-writing identical content must be a no-op: %v", err)
		}
	})

	t.Run("force renames, never deletes", func(t *testing.T) {
		if err := core.WriteKeyFile(p, []byte("second"), 0o600, true); err != nil {
			t.Fatalf("--force: %v", err)
		}
		if b, _ := os.ReadFile(p + ".old"); string(b) != "first" {
			t.Fatalf("the replaced key must survive at .old, got %q", b)
		}
		if b, _ := os.ReadFile(p); string(b) != "second" {
			t.Fatalf("new content = %q", b)
		}
		// A second --force would have to clobber the .old copy: refuse instead. This function
		// destroys key material under no circumstances.
		if err := core.WriteKeyFile(p, []byte("third"), 0o600, true); err == nil {
			t.Fatal("--force overwrote the .old backup")
		}
	})

	t.Run("an existing permissive file is refused, not adopted", func(t *testing.T) {
		q := filepath.Join(dir, "bob.key")
		if err := os.WriteFile(q, []byte("placeholder"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := core.WriteKeyFile(q, []byte("seed"), 0o600, false); err == nil {
			t.Fatal("wrote a private seed into a pre-existing file")
		}
		if fi, _ := os.Stat(q); fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode changed to %v - the file should be untouched", fi.Mode().Perm())
		}
		if b, _ := os.ReadFile(q); string(b) != "placeholder" {
			t.Fatalf("content changed to %q", b)
		}
	})

	t.Run("an unreadable destination is not treated as absent", func(t *testing.T) {
		// The AUD-06 shape: a read error silently becoming "nothing here, generate a fresh one".
		d := filepath.Join(dir, "adir.key")
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := core.WriteKeyFile(d, []byte("seed"), 0o600, false); err == nil {
			t.Fatal("a directory in the key's place was treated as an absent key")
		}
	})
}
