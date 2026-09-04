package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI face of SPEC §8.1. Two properties matter more than the happy path:
// an unknown scheme must be CARRIED (refusing it would make the scheme list a protocol version),
// and nothing here may ever present stored evidence as verified.
func TestAttachAndListMaterial(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	t.Setenv("NEKTON_DIR", reg)
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("9a", 32)}); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := seed([]string{"lab/qc", "--sign", filepath.Join(dir, "k.key"),
			"--when", "2026-07-16T00:00:00Z", "--add", "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))

	evidence := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(evidence, []byte(`{"pretend":"bundle"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// A listed scheme infers its media type; an unknown one is accepted but must say how to read it.
	if err := attachMaterial([]string{id, "--scheme", "sigstore-bundle", "--file", evidence}); err != nil {
		t.Fatalf("attach known scheme: %v", err)
	}
	if err := attachMaterial([]string{id, "--scheme", "invented-in-2031", "--file", evidence}); err == nil {
		t.Error("an unknown scheme was accepted with no --media; a reader would not know how to read it")
	}
	if err := attachMaterial([]string{id, "--scheme", "invented-in-2031",
		"--media", "application/octet-stream", "--file", evidence}); err != nil {
		t.Fatalf("an unknown scheme with --media was REJECTED (§8.1 requires it be carried): %v", err)
	}

	// Material binds to a content address, never to a name.
	if err := attachMaterial([]string{"sha256:" + strings.Repeat("e", 64),
		"--scheme", "rfc3161", "--file", evidence}); err == nil {
		t.Error("material was attached to a subject this registry does not hold")
	}

	var got struct {
		Subject  string `json:"subject"`
		Material []struct {
			Scheme    string `json:"scheme"`
			MediaType string `json:"mediaType"`
			Material  string `json:"material"`
			Verified  bool   `json:"verified"`
		} `json:"material"`
	}
	raw := captureStdout(t, func() {
		if err := listMaterial([]string{id, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	if len(got.Material) != 2 {
		t.Fatalf("material = %d entries, want 2", len(got.Material))
	}
	for _, m := range got.Material {
		// The kernel stores evidence; it never evaluates it. Reporting anything else here would be
		// the one lie this whole clause exists to prevent.
		if m.Verified {
			t.Errorf("%s reported as verified - the kernel evaluates nothing (§8.1, §15)", m.Scheme)
		}
		b, err := base64.StdEncoding.DecodeString(m.Material)
		if err != nil || string(b) != `{"pretend":"bundle"}` {
			t.Errorf("%s: bytes did not survive the round trip: %v", m.Scheme, err)
		}
	}
}
