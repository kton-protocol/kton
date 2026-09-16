package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A command that SUCCEEDS while doing something other than what was asked is worse than one that
// fails: the caller gets no signal, and the wrong thing is now signed, stored, or named. These are
// the three ways that happened in argument parsing, each verified against the real behaviour before
// the fix.
func TestFlagShapedArgumentsAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("ef", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"uri":"urn:x"}],`+
		`"predicate":"https://kton.dev/v/note","object":{"a":"1"},`+
		`"by":"CN=t","when":"2026-07-16T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// `claim` takes its output as a THIRD POSITIONAL while `seed` and `annotate` take -o, so one
	// verb in three punishes the habit the other two teach. `-o` was accepted as the filename: the
	// envelope landed in a file literally named "-o", the requested path was dropped, and the
	// command printed "-> -o" as though that were the plan. Without --add the record then existed
	// nowhere the caller was looking.
	t.Run("claim refuses -o instead of writing a file named -o", func(t *testing.T) {
		want := filepath.Join(dir, "out.dsse.json")
		err := run("claim", []string{spec, key, "-o", want})
		if err == nil {
			t.Fatal("claim accepted -o as a positional")
		}
		if !strings.Contains(err.Error(), "THIRD POSITIONAL") {
			t.Errorf("the refusal does not say what to do instead: %v", err)
		}
		if _, serr := os.Stat(filepath.Join(dir, "-o")); serr == nil {
			t.Error(`a file named "-o" was written`)
		}
	})

	// seed guarded `--` only, so `-x` fell through to the positional branch and BECAME the scope
	// name. A scope name is identity: it goes into the seed's canonical bytes and therefore into the
	// scope id that every scoped claim names.
	t.Run("seed refuses a single-dash flag", func(t *testing.T) {
		err := run("seed", []string{"sc", "-x", "v", "--sign", key})
		if err == nil {
			t.Fatal(`seed accepted "-x" and opened a scope named "v"`)
		}
		if !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("wrong refusal: %v", err)
		}
	})

	// LAST-WINS is how a scope silently becomes a different scope - the same defect #45 fixed in
	// `templates`, where any positional was read as a template name.
	t.Run("seed refuses a second scope name", func(t *testing.T) {
		err := run("seed", []string{"sc", "extra", "--sign", key})
		if err == nil {
			t.Fatal("seed took two names and used one of them silently")
		}
		if !strings.Contains(err.Error(), "part of the scope id") {
			t.Errorf("the refusal does not say why it matters: %v", err)
		}
	})

	// And the normal paths must still work - a gate that refuses them is the failure this repository
	// keeps finding.
	t.Run("the forms that were always correct still work", func(t *testing.T) {
		out := filepath.Join(dir, "ok.dsse.json")
		if err := run("claim", []string{spec, key, out}); err != nil {
			t.Fatalf("third-positional output refused: %v", err)
		}
		if _, err := os.Stat(out); err != nil {
			t.Errorf("no envelope at %s: %v", out, err)
		}
		t.Setenv("NEKTON_DIR", filepath.Join(dir, "reg"))
		if err := run("seed", []string{"sc", "--sign", key, "-o", filepath.Join(dir, "seed.json")}); err != nil {
			t.Errorf("a plain seed with -o was refused: %v", err)
		}
	})
}

// SPEC §12: "An unrecognised or absent query parameter MUST be an error, never an empty result: an
// empty answer to a malformed question is a successful wrong answer." `material` asked about a
// RECORD and answered "(none) - no verification material attached to -x" with exit 0. A caller
// checking whether a record carries evidence reads that as "checked, none there" - a different fact
// from "that is not a record id".
func TestMaterialRefusesAMalformedRecordID(t *testing.T) {
	t.Setenv("NEKTON_DIR", t.TempDir())
	for _, bad := range []string{"-x", "not-a-hash", "sha256:abc"} {
		if err := run("material", []string{bad}); err == nil {
			t.Errorf("material %q answered instead of refusing", bad)
		}
	}
	// A real id with nothing attached is NOT an error: "no material" is a true answer about a
	// record that could have some.
	if err := run("material", []string{"sha256:" + strings.Repeat("ab", 32)}); err != nil {
		t.Errorf("a well-formed id with no material was refused: %v", err)
	}
}
