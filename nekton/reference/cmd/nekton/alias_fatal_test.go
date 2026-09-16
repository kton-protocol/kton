package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAMalformedAliasFileIsFatalEverywhere: an alias file that was meant to define meanings and does
// not parse must never be silently ignored — with no aliases nothing resolves, and what follows is
// either a bare term emitted as an IRI into published RDF or a query answering "none" for records
// the store holds.
//
// It was made fatal in `mustTemplateSet` and left reachable in `resolvePredicateArg` one function
// over, because only the missing-DIRECTORY case was fixed there. This test covers both paths at once
// so the next person cannot fix one and miss the other: the loop is over the COMMANDS, not over the
// functions.
//
// An ABSENT alias file stays fine and is asserted here too — that distinction is the whole point,
// and a gate that refused it would break every caller who simply has no aliases.
func TestAMalformedAliasFileIsFatalEverywhere(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("c1", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	t.Setenv("NEKTON_DIR", filepath.Join(dir, "reg"))
	// No template directory: that is the ordinary case for these commands, and it must cost
	// templates, not aliases.
	t.Setenv("NEKTON_TEMPLATES", filepath.Join(dir, "no-such-templates"))

	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"uri":"urn:x"}],`+
		`"predicate":"https://kton.dev/v/qa/reviewed","object":{"a":"1"},`+
		`"by":"CN=t","when":"2026-07-16T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := run("claim", []string{spec, key, "--add", "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))

	good := filepath.Join(dir, "aliases.json")
	if err := os.WriteFile(good, []byte(`{"prefixes":{"qa":"https://kton.dev/v/qa/"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(bad, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "nope.json")

	out := filepath.Join(dir, "out.trig")
	cmds := []struct {
		name string
		with func(aliases string) error
	}{
		{"by predicate", func(a string) error {
			t.Setenv("NEKTON_ALIASES", a)
			return run("by", []string{"predicate", "qa:reviewed", "--json"})
		}},
		{"export --nanopub", func(a string) error {
			return run("export", []string{"--nanopub", id, "--aliases", a, "-o", out})
		}},
		{"nanopublish", func(a string) error {
			return run("nanopublish", []string{id, "--aliases", a, "-o", out})
		}},
	}

	for _, c := range cmds {
		t.Run(c.name+" refuses a malformed alias file", func(t *testing.T) {
			err := c.with(bad)
			if err == nil {
				t.Fatal("a malformed alias file was ignored - every CURIE then resolves to itself, so " +
					"this either emits a bare term as an IRI or answers \"none\" for records held")
			}
			if !strings.Contains(err.Error(), "alias file") {
				t.Errorf("the refusal does not name the alias file: %v", err)
			}
		})
		t.Run(c.name+" accepts a valid one", func(t *testing.T) {
			if err := c.with(good); err != nil {
				t.Errorf("a valid alias file was refused: %v", err)
			}
		})
		t.Run(c.name+" accepts an absent one", func(t *testing.T) {
			if err := c.with(absent); err != nil {
				t.Errorf("an absent alias file must just mean no sugar: %v", err)
			}
		})
	}
}
