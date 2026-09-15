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

	w, err := core.WriteKeyFile(p, []byte("first"), 0o600, false)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	// The assertion is not "the mode is 0600" - on Windows it is 0666 and no amount of asking
	// changes that. It is that the code KNOWS which of the two happened, because every claim this
	// project makes about private keys rests on the mode and the one unacceptable outcome is
	// asserting protection without looking. Either the request was honoured, or the shortfall is
	// reported; silently neither is the bug.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	got := fi.Mode().Perm()
	switch {
	case got&^0o600 == 0:
		if w.ModeUnenforced != 0 {
			t.Errorf("mode %v honours the 0600 request, but ModeUnenforced reports %v", got, w.ModeUnenforced)
		}
	default:
		if w.ModeUnenforced != got {
			t.Errorf("mode is %v, which grants more than the requested 0600, and ModeUnenforced says %v - "+
				"a caller would tell its user the key is protected when it is not", got, w.ModeUnenforced)
		}
		t.Logf("this platform does not enforce 0600 (got %v); WriteKeyFile reports it, which is the "+
			"contract being tested here", got)
	}

	t.Run("a different key is refused and the bytes are untouched", func(t *testing.T) {
		if _, err := core.WriteKeyFile(p, []byte("second"), 0o600, false); err == nil {
			t.Fatal("overwrote an existing identity")
		}
		if b, _ := os.ReadFile(p); string(b) != "first" {
			t.Fatalf("existing key was modified: %q", b)
		}
	})

	t.Run("the same key is idempotent", func(t *testing.T) {
		// A deterministic `--seed` re-run must not need --force: reproducible snapshots depend on
		// generating the same identity twice.
		if _, err := core.WriteKeyFile(p, []byte("first"), 0o600, false); err != nil {
			t.Fatalf("re-writing identical content must be a no-op: %v", err)
		}
	})

	t.Run("force renames, never deletes", func(t *testing.T) {
		if _, err := core.WriteKeyFile(p, []byte("second"), 0o600, true); err != nil {
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
		if _, err := core.WriteKeyFile(p, []byte("third"), 0o600, true); err == nil {
			t.Fatal("--force overwrote the .old backup")
		}
	})

	t.Run("an existing permissive file is refused, not adopted", func(t *testing.T) {
		q := filepath.Join(dir, "bob.key")
		if err := os.WriteFile(q, []byte("placeholder"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The property is UNTOUCHED, not 0644. Asserting the literal baked in a Unix assumption:
		// Windows reports 0666 for any writable file regardless of what the create asked for, so the
		// test failed there over something the code never did.
		before, err := os.Stat(q)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := core.WriteKeyFile(q, []byte("seed"), 0o600, false); err == nil {
			t.Fatal("wrote a private seed into a pre-existing file")
		}
		if fi, _ := os.Stat(q); fi.Mode().Perm() != before.Mode().Perm() {
			t.Fatalf("mode changed from %v to %v - the file should be untouched",
				before.Mode().Perm(), fi.Mode().Perm())
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
		if _, err := core.WriteKeyFile(d, []byte("seed"), 0o600, false); err == nil {
			t.Fatal("a directory in the key's place was treated as an absent key")
		}
	})
}
