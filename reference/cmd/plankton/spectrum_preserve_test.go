package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `spectrum define` EXTENDS an existing manifest. It read the file and treated every error as "not
// there yet", so a manifest that was malformed, truncated or unreadable was replaced by a fresh one
// holding only what this invocation named - a qualification corpus silently reduced, with a later
// check then run over fewer cases than the operator believed. A file we cannot read is not a file
// that is not there.
func TestSpectrumDefinePreservesAManifestItCannotRead(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "tool.spectrum.json")
	h := "sha256:" + strings.Repeat("a", 64)

	t.Run("a malformed manifest is preserved, not replaced", func(t *testing.T) {
		// A real manifest missing its final brace: the shape a half-finished edit or a truncated
		// copy leaves behind, and it names a member the operator cares about.
		broken := `{"spectrum":"tool","members":[{"name":"important-existing-case","hash":"` + h + `"}]`
		if err := os.WriteFile(m, []byte(broken), 0o644); err != nil {
			t.Fatal(err)
		}
		err := run("spectrum", []string{"define", "--id", "tool",
			"--member", "new-case=" + h, "-o", m})
		if err == nil {
			t.Error("define overwrote a manifest it could not parse")
		}
		got, rerr := os.ReadFile(m)
		if rerr != nil {
			t.Fatalf("the manifest is gone: %v", rerr)
		}
		if string(got) != broken {
			t.Errorf("the unreadable manifest was modified.\n got: %s\nwant: %s", got, broken)
		}
		if !strings.Contains(string(got), "important-existing-case") {
			t.Error("the existing member was lost")
		}
	})

	t.Run("an absent manifest still starts a fresh one", func(t *testing.T) {
		fresh := filepath.Join(dir, "new.spectrum.json")
		if err := run("spectrum", []string{"define", "--id", "tool",
			"--member", "case-a=" + h, "-o", fresh}); err != nil {
			t.Fatalf("define refused to create a new manifest: %v", err)
		}
		if _, err := os.Stat(fresh); err != nil {
			t.Fatalf("no manifest was written: %v", err)
		}
	})

	t.Run("a valid manifest is extended, keeping earlier members", func(t *testing.T) {
		v := filepath.Join(dir, "valid.spectrum.json")
		if err := run("spectrum", []string{"define", "--id", "tool",
			"--member", "first=" + h, "-o", v}); err != nil {
			t.Fatal(err)
		}
		if err := run("spectrum", []string{"define", "--id", "tool",
			"--member", "second=" + h, "-o", v}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"first", "second"} {
			if !strings.Contains(string(b), want) {
				t.Errorf("member %q was lost when the manifest was extended: %s", want, b)
			}
		}
	})
}
