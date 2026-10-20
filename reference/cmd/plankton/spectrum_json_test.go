package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// spectrum check is a gate, and its answer was prose only. --json carries the same answer: a status
// per member and the outcome, and nothing else on stdout.
func TestSpectrumCheckJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	for p, b := range map[string]string{in: "model+data", out: "gold"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("5a", 32)}); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "f.dsse.json")
	if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out,
		"--sign", filepath.Join(dir, "k.key"), "-o", env, "--add"}); err != nil {
		t.Fatal(err)
	}
	gold := core.HashBytes([]byte("gold"))
	manifest := filepath.Join(dir, "tool.spectrum.json")
	if err := run("spectrum", []string{"define", "--id", "tool", "--member", "m1=" + gold, "-o", manifest}); err != nil {
		t.Fatal(err)
	}
	raw := captureStdout(t, func() {
		if err := run("spectrum", []string{"check", manifest, "--candidate", "m1=" + gold, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var got struct {
		Spectrum  string `json:"spectrum"`
		Fulfilled int    `json:"fulfilled"`
		Outcome   string `json:"outcome"`
		Members   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("spectrum check --json is not one JSON document: %v\n%s", err, raw)
	}
	if got.Spectrum != "tool" || got.Outcome != "fulfilled" || got.Fulfilled != 1 ||
		len(got.Members) != 1 || got.Members[0].Name != "m1" || got.Members[0].Status != "identical" {
		t.Errorf("spectrum check --json = %+v", got)
	}
}
