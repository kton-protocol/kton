package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoVerdictWithoutAVerifier: `false` and "not checked" are different facts, and a consumer reads
// `false` as CHECKED AND FAILED. SPEC §8.1's read-path boundary — a kernel's own output MUST NOT
// carry a field that reads as a verification verdict — is the rule; the material commands applied it
// this release and these outputs did not.
func TestNoVerdictWithoutAVerifier(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("3d", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	reg := filepath.Join(dir, "reg")
	t.Setenv("NEKTON_DIR", reg)

	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"uri":"urn:x"}],`+
		`"predicate":"https://kton.dev/v/note","object":{"a":"1"},"by":"CN=t",`+
		`"when":"2026-07-16T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run("claim", []string{spec, key, "--add"}); err != nil {
		t.Fatal(err)
	}

	t.Run("export without --trust-keys says unchecked, not false", func(t *testing.T) {
		out := filepath.Join(dir, "e.json")
		if err := run("export", []string{out}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var g struct {
			Claims []struct {
				SignerVerified string `json:"signerVerified"`
			} `json:"claims"`
		}
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, b)
		}
		if len(g.Claims) == 0 {
			t.Fatal("no claims exported")
		}
		if got := g.Claims[0].SignerVerified; got != "unchecked" {
			t.Errorf("signerVerified = %q with no --trust-keys; nobody was asked, so anything that "+
				"reads as a verdict is wrong", got)
		}
	})

	t.Run("export names what it holds but cannot assert", func(t *testing.T) {
		// A store whose only record is deferred must not answer as though it were empty.
		d2 := t.TempDir()
		t.Setenv("NEKTON_DIR", filepath.Join(d2, "reg"))
		seedFile := filepath.Join(d2, "seed.json")
		seedID := strings.TrimSpace(captureStdout(t, func() {
			if err := run("seed", []string{"sc", "--sign", key, "-o", seedFile, "--print-id"}); err != nil {
				t.Fatal(err)
			}
		}))
		sp := filepath.Join(d2, "c.json")
		if err := os.WriteFile(sp, []byte(`{"subject":[{"uri":"urn:y"}],`+
			`"predicate":"https://kton.dev/v/note","object":{"a":"1"},"by":"CN=t",`+
			`"when":"2026-07-16T00:00:00Z","scope":"`+seedID+`","prev":"`+seedID+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := run("claim", []string{sp, key, "--add"}); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(d2, "e.json")
		if err := run("export", []string{out}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(out)
		var g struct {
			Deferred int   `json:"deferred"`
			Claims   []any `json:"claims"`
		}
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatal(err)
		}
		if len(g.Claims) != 0 {
			t.Fatalf("a deferred claim was exported as an assertion: %d claims", len(g.Claims))
		}
		if g.Deferred != 1 {
			t.Errorf("deferred = %d; an empty `claims` with no count reads as \"this store has "+
				"nothing\", which is not what it holds", g.Deferred)
		}
	})
}
