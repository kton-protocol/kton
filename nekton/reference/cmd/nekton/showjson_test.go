package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nekton show was the last asymmetry against plankton show (#54, #57). --json carries the predicate
// body WHOLE, on the same principle: the human rendering names object/evidence/by/when/scope/prev,
// so anything else a claim carries is invisible there. A field that is never named cannot be
// forgotten.
func TestNektonShowJSON(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("cd", 32)}); err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("a", 64)
	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"hash":"`+subject+`"}],`+
		`"predicate":"https://kton.dev/v/note","object":{"x":"1"},`+
		`"by":"a","when":"2026-07-16T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "reg")
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := authorClaim(spec, filepath.Join(dir, "k.key"), "", true, reg, true); err != nil {
			t.Fatal(err)
		}
	}))

	t.Setenv("NEKTON_DIR", reg)
	raw := captureStdout(t, func() {
		if err := showClaim([]string{id, "--json"}); err != nil {
			t.Fatal(err)
		}
	})

	var got struct {
		ClaimID       string         `json:"claimId"`
		PredicateType string         `json:"predicateType"`
		Subject       []string       `json:"subject"`
		Predicate     map[string]any `json:"predicate"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	if got.ClaimID != id {
		t.Errorf("claimId = %q, want %q", got.ClaimID, id)
	}
	if len(got.Subject) != 1 || got.Subject[0] != subject {
		t.Errorf("subject = %v", got.Subject)
	}
	// The body arrives as data, not as prose to re-parse.
	if got.Predicate["by"] != "a" || got.Predicate["when"] != "2026-07-16T00:00:00Z" {
		t.Errorf("predicate body did not survive: %v", got.Predicate)
	}
	if obj, ok := got.Predicate["object"].(map[string]any); !ok || obj["x"] != "1" {
		t.Errorf("object did not survive: %v", got.Predicate["object"])
	}
}

// The head is what a consumer anchors or publishes, so it must be readable as data (#74). Both
// caveats travel as FIELDS rather than as prose a reader may skip.
func TestHeadJSON(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	t.Setenv("NEKTON_DIR", reg)
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("6b", 32)}); err != nil {
		t.Fatal(err)
	}
	scope := strings.TrimSpace(captureStdout(t, func() {
		if err := seed([]string{"lab/x", "--sign", filepath.Join(dir, "k.key"),
			"--when", "2026-07-16T00:00:00Z", "--registry", reg, "--add", "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))

	var got struct {
		Scope      string   `json:"scope"`
		Heads      []string `json:"heads"`
		Branched   bool     `json:"branched"`
		Unresolved int      `json:"unresolved"`
	}
	raw := captureStdout(t, func() {
		if err := run("head", []string{scope, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("head --json is not valid JSON: %v\n%s", err, raw)
	}
	if got.Scope != scope || len(got.Heads) != 1 || got.Heads[0] != scope {
		t.Errorf("head --json = %+v; a fresh scope's tip is its own seed", got)
	}
	if got.Branched || got.Unresolved != 0 {
		t.Errorf("branched/unresolved = %v/%d on a fresh scope", got.Branched, got.Unresolved)
	}

	// `sealed` must NOT be a field. A withheld LATER claim is undetectable in-band, so no value here
	// could say so honestly; that is settled by matching a published or anchored head.
	var loose map[string]any
	_ = json.Unmarshal([]byte(raw), &loose)
	if _, present := loose["sealed"]; present {
		t.Error("head --json carries a `sealed` field - tail truncation is undetectable in-band, so it cannot be answered here")
	}
}
