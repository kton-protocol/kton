package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `plankton material --json` had no test at all, and its shape was wrong: it emitted a fifth field,
// `"verified": false`, beside SPEC §8.1's four. The value was a constant, so it carried no
// information - and §8.1 says outright "The kernel MUST NOT interpret or verify `material`", so the
// kernel has no verdict to report in the first place. A consumer reads `verified: false` as CHECKED
// AND FAILED; the truth is that nobody looked. That is one word carrying two meanings, in the field
// a cockpit is most likely to key on.
//
// Asserted on the KEY SET rather than on a value, because a value assertion against a hardcoded
// constant cannot fail - which is exactly what the nekton-side test was doing.
func TestMaterialJSONCarriesOnlyTheFourFieldsOf81(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))

	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	for p, b := range map[string]string{in: "a", out: "b"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("c3", 32)}); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out,
			"--sign", filepath.Join(dir, "k.key"), "--add", "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))

	evidence := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(evidence, []byte(`{"pretend":"bundle"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A listed scheme and an unknown one: §8.1 requires the unknown one be CARRIED, not rejected,
	// so both must come back through --json with the same shape.
	if err := run("attach", []string{id, "--scheme", "sigstore-bundle", "--file", evidence}); err != nil {
		t.Fatalf("attach known scheme: %v", err)
	}
	if err := run("attach", []string{id, "--scheme", "acme-internal-badge-v3",
		"--media", "application/octet-stream", "--file", evidence}); err != nil {
		t.Fatalf("an unknown scheme with --media was REJECTED (§8.1 requires it be carried): %v", err)
	}

	var got struct {
		Subject  string           `json:"subject"`
		Material []map[string]any `json:"material"`
	}
	raw := captureStdout(t, func() {
		if err := run("material", []string{id, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("material --json is not valid JSON: %v\n%s", err, raw)
	}
	if len(got.Material) != 2 {
		t.Fatalf("material = %d entries, want 2 (the known scheme and the carried unknown one)", len(got.Material))
	}

	want := map[string]bool{"subject": true, "scheme": true, "mediaType": true, "material": true}
	for _, m := range got.Material {
		for k := range m {
			if !want[k] {
				t.Errorf("material carries %q; §8.1 defines only subject/scheme/mediaType/material, and "+
					"the kernel has no verdict to add", k)
			}
		}
		for k := range want {
			if _, ok := m[k]; !ok {
				t.Errorf("material is missing §8.1's %q", k)
			}
		}
	}
}
