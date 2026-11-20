package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nclaim "kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
)

// kton mirror nekton fails on a peer line that does not parse, as nekton mirror does since #286
// (#287): the copy is short by that line, and exit 0 would say it is whole.
func TestKtonMirrorNektonFailsOnAnUnreadablePeerLine(t *testing.T) {
	peer, local := t.TempDir(), t.TempDir()
	src, err := nreg.Open(peer)
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := nclaim.SignWith(nclaim.Spec{Subject: []nclaim.SubjectSpec{{URI: "urn:a"}}, Predicate: "https://kton.dev/v/x", By: "k", When: "2026-11-19T00:00:00Z"}, ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.Add(env); err != nil {
		t.Fatal(err)
	}
	if err := mirrorNekton(local, peer); err != nil {
		t.Fatalf("a whole peer: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(peer, "objects", "*.nekton.jsonl"))
	if len(files) == 0 {
		t.Fatal("no scope file in the peer")
	}
	fh, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(`{"claimId":"sha256:half` + "\n")
	fh.Close()
	err = mirrorNekton(local, peer)
	if err == nil || !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Fatalf("mirror of a peer with an unreadable line: %v, want an INCOMPLETE error", err)
	}
}
