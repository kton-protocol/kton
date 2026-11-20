package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

// A peer line that does not parse is copied by nobody, so `nekton mirror` says the copy is
// incomplete and fails, as it does for a refused claim (kton-review F2).
func TestMirrorFailsOnAnUnreadablePeerLine(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := registry.Open(src)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEKTON_DIR", dst)
	if err := run("mirror", []string{src}); err != nil {
		t.Fatalf("a whole peer: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(src, "objects", "*.nekton.jsonl"))
	if len(files) == 0 {
		t.Fatal("no scope file in the peer")
	}
	fh, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(`{"claimId":"sha256:half` + "\n")
	fh.Close()
	err = run("mirror", []string{src})
	if err == nil || !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Fatalf("mirror of a peer with an unreadable line: %v, want an INCOMPLETE error", err)
	}
}
