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
