package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestQueryCommandsRefuseLastWins: the positional hardening reached nekton's `annotate`, `attach` and
// `material` and stopped at the kernel boundary — in the very change that was fixing a
// plankton/nekton twin. plankton's query commands still took the LAST positional:
//
//	plankton producer <a> <b>       answered about <b>
//	plankton material <a> <b>       answered about <b>
//	plankton reproduces <a> <b> <c> compared <a> against <c>
//
// A question the caller did not ask, answered with no sign that the first argument was dropped. The
// §12 clause quoted in main.go rules out an empty answer to a malformed question for the same
// reason: answering the WRONG question is not better than answering a malformed one.
func TestQueryCommandsRefuseLastWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	ev := filepath.Join(dir, "ev.bin")
	if err := os.WriteFile(ev, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cmd  string
		args []string
		want string
	}{
		{"producer, two ids", "producer", []string{a, b}, "takes ONE"},
		{"uses, two ids", "uses", []string{a, b}, "takes ONE"},
		{"lineage, two ids", "lineage", []string{a, b}, "takes ONE"},
		{"material, two ids", "material", []string{a, b}, "takes ONE"},
		{"producer, single-dash flag", "producer", []string{a, "-x"}, "unknown flag"},
		{"attach, single-dash flag", "attach", []string{a, "-x", "--scheme", "rekor-entry", "--file", ev},
			"unknown flag"},
		{"material, single-dash flag", "material", []string{a, "-x"}, "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.cmd, tc.args)
			if err == nil {
				t.Fatalf("plankton %s accepted it and answered about the wrong argument", tc.cmd)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("wrong refusal: %v", err)
			}
		})
	}

	// The forms that were always correct must still work. A gate that refuses the normal path is the
	// failure this repository keeps finding, including in the commit this one is fixing.
	t.Run("one argument still works", func(t *testing.T) {
		for _, cmd := range []string{"producer", "uses", "lineage", "material"} {
			if err := run(cmd, []string{a}); err != nil {
				t.Errorf("plankton %s with one id was refused: %v", cmd, err)
			}
		}
		// NOT `reproduces` here: with two well-formed hashes it reaches its verdict path, which
		// signals "not reproduced" with os.Exit(1) - so an in-process call kills the test binary
		// before the framework reports anything. Its argument check is covered by the
		// three-hashes case above, which returns before that path.
	})
}

// TestReproducesArgs covers the `reproduces` parse directly, and the reason it is not exercised
// through run() belongs here: everything after the parse reaches a verdict path that ends in
// os.Exit(1) for "not reproduced". An in-process call of the whole command therefore cannot be
// mutation-checked - removing a guard would kill the test binary and the run would report NOTHING
// rather than a failure, which is a check that cannot fail. The first version of this test had
// exactly that shape.
//
// Spawning the binary instead would import os/exec into plankton, and the architecture guard
// refuses that - plankton documents, never executes - which is how the attempt was caught. A pure
// parse function satisfies both.
func TestReproducesArgs(t *testing.T) {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	c := "sha256:" + strings.Repeat("c", 64)

	t.Run("a third hash is refused", func(t *testing.T) {
		_, _, _, _, err := parseReproducesArgs([]string{a, b, c})
		if err == nil {
			t.Fatal("a third hash was accepted - it used to replace the candidate silently, so the " +
				"verdict was about a different pair than the one asked for")
		}
		if !strings.Contains(err.Error(), "compares TWO") {
			t.Errorf("wrong refusal: %v", err)
		}
	})

	t.Run("a single-dash flag is refused", func(t *testing.T) {
		if _, _, _, _, err := parseReproducesArgs([]string{a, b, "-x"}); err == nil {
			t.Error(`"-x" was taken as an argument`)
		}
	})

	t.Run("one hash is refused", func(t *testing.T) {
		if _, _, _, _, err := parseReproducesArgs([]string{a}); err == nil {
			t.Error("a single hash was accepted; reproduces compares two")
		}
	})

	t.Run("the correct forms parse", func(t *testing.T) {
		gotRef, gotCand, via, asJSON, err := parseReproducesArgs([]string{a, b})
		if err != nil || gotRef != a || gotCand != b || via != "" || asJSON {
			t.Errorf("parse(%s %s) = %q %q %q %v, err=%v", a, b, gotRef, gotCand, via, asJSON, err)
		}
		gotRef, gotCand, via, asJSON, err = parseReproducesArgs([]string{a, b, "--via", c, "--json"})
		if err != nil || gotRef != a || gotCand != b || via != c || !asJSON {
			t.Errorf("parse with --via/--json = %q %q %q %v, err=%v", gotRef, gotCand, via, asJSON, err)
		}
	})
}
