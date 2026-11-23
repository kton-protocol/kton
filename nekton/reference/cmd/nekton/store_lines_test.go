package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

// #287: `nekton verify --store` names the unreadable lines and reports how many, so the caller
// can exit 5; a whole store reports none.
func TestVerifyStoreNamesUnreadableLines(t *testing.T) {
	dir := t.TempDir()
	r, _ := registry.Open(dir)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if n, err := storeLinesReport(&out, dir, false); err != nil || n != 0 || !strings.Contains(out.String(), "every line parses") {
		t.Fatalf("whole store: n=%d err=%v out=%q", n, err, out.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "objects", "*.nekton.jsonl"))
	fh, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(`{"claimId":"sha256:half` + "\n")
	fh.Close()

	out.Reset()
	n, err := storeLinesReport(&out, dir, false)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1", n, err)
	}
	if s := out.String(); !strings.Contains(s, filepath.Base(files[0])+":") || !strings.Contains(s, `sha256:half`) {
		t.Errorf("the report does not name the file and the line: %q", s)
	}
	out.Reset()
	if n, err := storeLinesReport(&out, dir, true); err != nil || n != 1 {
		t.Fatalf("--json: n=%d err=%v", n, err)
	}
	var j struct {
		Unreadable []registry.UnreadableLine `json:"unreadable"`
	}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil || len(j.Unreadable) != 1 || j.Unreadable[0].Line == 0 {
		t.Errorf("--json: %v %+v", err, j)
	}
}
