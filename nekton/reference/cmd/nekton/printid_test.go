package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var bareID = regexp.MustCompile(`^sha256:[0-9a-f]{64}\n$`)

// annotate and seed mint an identifier a caller needs - the claim id, the scope id - and used to
// embed it in prose on STDOUT, with no machine-readable way out (#56). The cockpit was parsing it
// back out, anchored on the "indexed claim" line: a dependency on output formatting that nothing
// guaranteed and no test protected.
//
// --print-id follows `plankton author --print-id` exactly (plankton main.go:33): the ONLY thing on
// stdout is the bare id, every human line goes to stderr.
func TestPrintIDPutsNothingButTheIDOnStdout(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k.key")
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "reg")
	subject := "sha256:" + strings.Repeat("c", 64)

	cases := []struct {
		name string
		run  func() error
	}{
		{"seed", func() error {
			return seed([]string{"demo", "--sign", key, "--when", "2026-07-16T00:00:00Z",
				"--registry", reg, "--add", "--print-id"})
		}},
		{"annotate", func() error {
			return annotate([]string{subject, "--template", "t", "--templates-dir", dir,
				"--sign", key, "--when", "2026-07-16T00:00:00Z", "--registry", reg, "--add", "--print-id"})
		}},
	}

	// annotate needs a template on disk.
	if err := os.WriteFile(filepath.Join(dir, "t.json"),
		[]byte(`{"predicate":"https://kton.dev/v/note","subject_kind":"foton"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range cases {
		var err error
		out := captureStdout(t, func() { err = c.run() })
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bareID.MatchString(out) {
			t.Errorf("%s --print-id stdout = %q; want exactly one bare sha256 id and nothing else", c.name, out)
		}
	}
}

// Without the flag the human output must be unchanged - --print-id redirects, it does not silence.
func TestWithoutPrintIDTheHumanLinesStayOnStdout(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	var err error
	out := captureStdout(t, func() {
		err = seed([]string{"demo", "--sign", filepath.Join(dir, "k.key"),
			"--when", "2026-07-16T00:00:00Z", "--registry", filepath.Join(dir, "reg"), "--add"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"seed scope", "claim sha256:", "SCOPE id"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain output lost %q:\n%s", want, out)
		}
	}
}
