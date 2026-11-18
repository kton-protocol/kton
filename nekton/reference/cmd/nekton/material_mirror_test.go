package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

// nekton mirror carries a claim's §8.1 material with it, once (#225).
func TestMirrorCarriesMaterial(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := registry.Open(src)
	id, _, err := r.Add(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AttachMaterial(registry.VerificationMaterial{Subject: id, Scheme: "rekor-entry", MediaType: "application/json",
		Material: base64.StdEncoding.EncodeToString([]byte(`{"entry":1}`))}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEKTON_DIR", dst)
	for i := 0; i < 2; i++ {
		if err := run("mirror", []string{src}); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := registry.Open(dst)
	if n := len(d.Material(id)); n != 1 {
		t.Fatalf("peer holds %d material attachment(s) after two mirrors, want 1", n)
	}
}
