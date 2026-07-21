package main

import (
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/registry"
)

// TestAuthorAddIngests: `plankton author ... --add --registry <dir>` signs and ingests in one step,
// into the named registry, without writing an intermediate envelope file.
func TestAuthorAddIngests(t *testing.T) {
	d := t.TempDir()
	in := filepath.Join(d, "in.txt")
	out := filepath.Join(d, "out.txt")
	if err := os.WriteFile(in, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(d, "reg")
	if err := authorConvenience([]string{"--cmd", "run", "--in", in, "--out", out, "--add", "--registry", reg}); err != nil {
		t.Fatalf("author --add: %v", err)
	}
	r, err := registry.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("want 1 foton ingested into the --registry, got %d", r.Len())
	}
}
