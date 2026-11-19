package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	nclaim "kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
	preg "kton.dev/plankton/registry"
)

// kton mirror re-added envelopes only, so the verification material plankton mirror and nekton mirror
// carry (#225) was dropped: a copy made with kton mirror had no kton-env/kton-locator material, and a
// locator check against it failed (kton-cockpit uat/e2e, 19.11.).
func TestKtonMirrorCarriesMaterial(t *testing.T) {
	mat := base64.StdEncoding.EncodeToString([]byte(`{"locator":"file:///data/out.csv"}`))

	t.Run("plankton", func(t *testing.T) {
		peer, local := t.TempDir(), t.TempDir()
		src, err := preg.Open(peer)
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := src.Add(variant(t, nil))
		if err != nil {
			t.Fatal(err)
		}
		vm := preg.VerificationMaterial{Subject: id, Scheme: "kton-locator/v1", MediaType: "application/json", Material: mat}
		if err := src.AttachMaterial(vm); err != nil {
			t.Fatal(err)
		}
		if err := mirrorPlankton(local, peer); err != nil {
			t.Fatal(err)
		}
		dst, _ := preg.Open(local)
		if got := dst.Material(id); len(got) != 1 || got[0] != vm {
			t.Fatalf("material after kton mirror plankton = %v, want [%v]", got, vm)
		}
		if err := mirrorPlankton(local, peer); err != nil { // again: nothing doubled
			t.Fatal(err)
		}
		if dst, _ = preg.Open(local); len(dst.Material(id)) != 1 {
			t.Fatalf("a second mirror doubled the material: %v", dst.Material(id))
		}
	})

	t.Run("nekton", func(t *testing.T) {
		peer, local := t.TempDir(), t.TempDir()
		src, err := nreg.Open(peer)
		if err != nil {
			t.Fatal(err)
		}
		env, _, err := nclaim.SignWith(nclaim.Spec{Subject: []nclaim.SubjectSpec{{URI: "urn:a"}}, Predicate: "https://kton.dev/v/x", By: "k", When: "2026-11-19T00:00:00Z"}, ed25519.NewKeyFromSeed(make([]byte, 32)))
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := src.Add(env)
		if err != nil {
			t.Fatal(err)
		}
		vm := nreg.VerificationMaterial{Subject: id, Scheme: "kton-env/v1", MediaType: "application/json", Material: mat}
		if err := src.AttachMaterial(vm); err != nil {
			t.Fatal(err)
		}
		if err := mirrorNekton(local, peer); err != nil {
			t.Fatal(err)
		}
		dst, _ := nreg.Open(local)
		if got := dst.Material(id); len(got) != 1 || got[0] != vm {
			t.Fatalf("material after kton mirror nekton = %v, want [%v]", got, vm)
		}
	})
}
