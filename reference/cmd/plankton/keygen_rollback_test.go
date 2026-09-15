package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keygen used to remove name+".key" unconditionally when the public half failed to write - including
// a private key it had never created. Re-running keygen over an existing identity whose .pub had
// drifted therefore DELETED the private key, while printing that it had protected one (dev review
// R04). The error text promised "refusing to overwrite an identity" and "would destroy the only copy
// of that private seed" in the same breath as destroying it.
//
// The four cases the rollback has to keep apart, because each needs a different answer:
func TestKeygenRollsBackOnlyWhatItWrote(t *testing.T) {
	seed := strings.Repeat("7b", 32)

	// 1. A pre-existing private key this call did not write MUST survive a public-half failure.
	t.Run("existing private key survives a conflicting .pub", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "k")
		if err := keygen([]string{name, "--seed", seed}); err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(name + ".key")
		if err != nil {
			t.Fatal(err)
		}
		// The public half drifts - a restored backup, a hand-edit, a half-finished copy.
		if err := os.WriteFile(name+".pub", []byte("a-different-public-key"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := keygen([]string{name, "--seed", seed}); err == nil {
			t.Fatal("keygen accepted a .pub holding a different key")
		}
		got, err := os.ReadFile(name + ".key")
		if err != nil {
			t.Fatalf("the pre-existing private key was DELETED by a failed keygen: %v", err)
		}
		if string(got) != string(want) {
			t.Error("the pre-existing private key was modified by a failed keygen")
		}
	})

	// 2. A private key this call DID create must not be left behind without its public half.
	t.Run("a half-written keypair is rolled back", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "k")
		// Make the .pub path unwritable by making it a directory: the write fails, the .key is ours.
		if err := os.Mkdir(name+".pub", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := keygen([]string{name, "--seed", seed}); err == nil {
			t.Fatal("keygen succeeded with an unwritable .pub path")
		}
		if _, err := os.Stat(name + ".key"); !os.IsNotExist(err) {
			t.Error("a private key this call created was left behind with no public half")
		}
	})

	// 3. --force renames the old key aside; if the public half then fails, the ORIGINAL identity
	//    must come back - not the new one, and not nothing.
	t.Run("a forced replacement restores the original on failure", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "k")
		if err := keygen([]string{name, "--seed", seed}); err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(name + ".key")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(name + ".pub"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(name+".pub", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := keygen([]string{name, "--seed", strings.Repeat("c4", 32), "--force"}); err == nil {
			t.Fatal("keygen succeeded with an unwritable .pub path")
		}
		got, err := os.ReadFile(name + ".key")
		if err != nil {
			t.Fatalf("a forced replacement that failed left NO private key: %v", err)
		}
		if string(got) != string(original) {
			t.Error("a forced replacement that failed did not restore the original private key")
		}
	})

	// 4. The ordinary idempotent re-run still works and still touches nothing.
	t.Run("an identical re-run stays idempotent", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "k")
		if err := keygen([]string{name, "--seed", seed}); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(name + ".key")
		if err != nil {
			t.Fatal(err)
		}
		if err := keygen([]string{name, "--seed", seed}); err != nil {
			t.Fatalf("a deterministic re-run stopped being idempotent: %v", err)
		}
		after, err := os.ReadFile(name + ".key")
		if err != nil || string(after) != string(before) {
			t.Error("an identical re-run changed the private key")
		}
	})
}
