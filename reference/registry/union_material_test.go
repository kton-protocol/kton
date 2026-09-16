package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// OpenUnion must fill the material map it allocates: an empty one leaves a foton with one
// attachment had ONE item read alone and ZERO as soon as any second source was added - including a
// completely empty one. §8.1 makes producing material optional; silently losing evidence the named
// sources hold, through an advertised union API, is a different thing.
func TestUnionMergesMaterialFromEverySource(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in, out := filepath.Join(t.TempDir(), "in"), filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(in, []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("out"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := foton.Spec{
		Inputs:   []foton.FileSpec{{Path: "in", Hash: core.HashBytes([]byte("in"))}},
		Outputs:  []foton.FileSpec{{Path: "out", Hash: core.HashBytes([]byte("out"))}},
		Protocol: &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"command": "noop"}},
	}
	env, fid, err := foton.SignWith(spec, priv)
	if err != nil {
		t.Fatal(err)
	}

	held, empty := t.TempDir(), t.TempDir()
	r, err := registry.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	att := registry.VerificationMaterial{Subject: fid, Scheme: "test-scheme", Material: "eA=="}
	if err := r.AttachMaterial(att); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Open(empty); err != nil {
		t.Fatal(err)
	}

	if n := len(r.Material(fid)); n != 1 {
		t.Fatalf("read alone: %d attachment(s), want 1 - the fixture is wrong", n)
	}
	for name, dirs := range map[string][]string{
		"empty source behind":   {held, empty},
		"empty source first":    {empty, held},
		"the same source twice": {held, held},
	} {
		t.Run(name, func(t *testing.T) {
			u, err := registry.OpenUnion(dirs...)
			if err != nil {
				t.Fatal(err)
			}
			got := u.Material(fid)
			if len(got) != 1 {
				t.Fatalf("%d attachment(s), want exactly 1 (identical evidence must not double either)", len(got))
			}
			if got[0].Scheme != "test-scheme" {
				t.Errorf("scheme = %q, want the attached one carried through", got[0].Scheme)
			}
		})
	}
}
