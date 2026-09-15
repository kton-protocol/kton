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
		} `json:"material"`
	}
	// Decoded a SECOND time as raw maps, because the typed struct above cannot see a field it does
	// not declare - and the key set is exactly what this test is about.
	var raw2 struct {
		Material []map[string]any `json:"material"`
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
	if err := json.Unmarshal([]byte(raw), &raw2); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	// SPEC §8.1 defines VerificationMaterial as four fields. The kernel MUST NOT interpret or verify
	// material, so it has no verdict to report and must not emit a field shaped like one: a `verified`
	// key reads as CHECKED AND FAILED, when the truth is that nobody looked.
	//
	// Asserted on the KEY SET, not on a value. The previous version of this test read the field into
	// a bool and checked it was false - against a hardcoded `false`. It could not fail, which is the
	// defect this suite keeps finding elsewhere and had here too.
	want := map[string]bool{"subject": true, "scheme": true, "mediaType": true, "material": true}
	for _, m := range raw2.Material {
		for k := range m {
			if !want[k] {
				t.Errorf("material carries %q; §8.1 defines only subject/scheme/mediaType/material", k)
			}
		}
		for k := range want {
			if _, ok := m[k]; !ok {
				t.Errorf("material is missing §8.1's %q", k)
			}
		}
	}
	for _, m := range got.Material {
		b, err := base64.StdEncoding.DecodeString(m.Material)
		if err != nil || string(b) != `{"pretend":"bundle"}` {
			t.Errorf("%s: bytes did not survive the round trip: %v", m.Scheme, err)
		}
	}
}
