package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSubjectTakingCommandsRefuseLastWins: the argument hardening landed on `seed` and `claim` and
// stopped there. `annotate`, `attach` and `material` still rejected only "--"-prefixed tokens and let
// the LAST positional win, so
//
//	nekton annotate <a> <b> --template qa/review …
//
// signed a claim about <b> and said nothing. The argument for refusing this on `seed` was that a
// scope name is identity; a claim's SUBJECT is what the claim is about, is covered by the claim id,
// and is signed. It is not the smaller case.
func TestSubjectTakingCommandsRefuseLastWins(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("7c", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	tdir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tdir, "qa-review.json"), []byte(
		`{"name":"qa/review","target":"foton","predicate":"https://kton.dev/v/qa/reviewed",`+
			`"fields":{"outcome":{"type":"enum","required":true,"values":["pass","fail"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEKTON_TEMPLATES", tdir)
	t.Setenv("NEKTON_ALIASES", filepath.Join(dir, "aliases.json"))
	t.Setenv("NEKTON_DIR", filepath.Join(dir, "reg"))

	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	ev := filepath.Join(dir, "ev.bin")
	if err := os.WriteFile(ev, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		cmd  string
		want string
	}{
		{"annotate, two subjects", []string{a, b, "--template", "qa/review", "--set", "outcome=pass",
			"--sign", key}, "annotate", "takes ONE subject"},
		{"annotate, single-dash flag", []string{a, "-x", "--template", "qa/review", "--set",
			"outcome=pass", "--sign", key}, "annotate", "unknown flag"},
		{"attach, single-dash flag", []string{a, "-x", "--scheme", "rekor-entry", "--file", ev},
			"attach", "unknown flag"},
		{"material, two ids", []string{a, b}, "material", "takes ONE record id"},
		{"material, single-dash flag", []string{a, "-x"}, "material", "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.cmd, tc.args)
			if err == nil {
				t.Fatalf("%s accepted it", tc.cmd)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("wrong refusal: %v", err)
			}
		})
	}

	// And the normal forms still work - a gate that refuses the normal path is the failure this
	// repository keeps finding.
	t.Run("one subject still works", func(t *testing.T) {
		if err := run("annotate", []string{a, "--template", "qa/review", "--set", "outcome=pass",
			"--by", "CN=t", "--when", "2026-07-16T00:00:00Z", "--sign", key,
			"-o", filepath.Join(dir, "out.json")}); err != nil {
			t.Errorf("a single-subject annotate was refused: %v", err)
		}
		if err := run("material", []string{a}); err != nil {
			t.Errorf("a single-id material was refused: %v", err)
		}
	})
}
