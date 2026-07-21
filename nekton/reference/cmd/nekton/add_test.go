package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/nekton/registry"
)

// TestClaimAddIngests: signClaim with addFlag ingests the claim into the named registry in one step,
// without writing an intermediate envelope file (the `nekton claim/annotate/seed --add` path).
func TestClaimAddIngests(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(t.TempDir(), "reg")
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "urn:example:thing"}},
		Predicate: "pav:reviewedBy",
		Object:    map[string]any{"value": "ok"},
		By:        "CN=Tester",
		When:      "2026-07-15T00:00:00Z",
	}
	if err := signClaim(spec, priv, "", true /* add */, reg); err != nil {
		t.Fatalf("claim --add: %v", err)
	}
	r, err := registry.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("want 1 claim ingested into the --registry, got %d", r.Len())
	}
}

// TestCoSignerTwinUnion: two independent co-signers of one IDENTICAL statement share a claim id (the
// id covers only the payload, not the signatures). Ingesting both - in either order - must yield ONE
// claim carrying BOTH signatures: each signer is found by `by signer`, each verifies, and the stored
// object bytes are order-independent (SPEC §12 conflict-free union). Regression for mirror-order-v2,
// where the first-ingested signature won and the other valid co-signature was silently dropped.
func TestCoSignerTwinUnion(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "https://ex.example/thing"}},
		Predicate: "https://kton.dev/v/endorses",
		Object:    map[string]any{"id": "did:web:x.example/y"},
		By:        "CN=board",
		When:      "2026-01-01T00:00:00Z",
	}
	dir := t.TempDir()
	envAPath := filepath.Join(dir, "a.dsse.json")
	envBPath := filepath.Join(dir, "b.dsse.json")
	if err := signClaim(spec, privA, envAPath, false, ""); err != nil {
		t.Fatalf("sign A: %v", err)
	}
	if err := signClaim(spec, privB, envBPath, false, ""); err != nil {
		t.Fatalf("sign B: %v", err)
	}
	envA, err := readEnvelope(envAPath)
	if err != nil {
		t.Fatal(err)
	}
	envB, err := readEnvelope(envBPath)
	if err != nil {
		t.Fatal(err)
	}
	kidA, kidB := keyidHex(pubA), keyidHex(pubB)

	var objBytes [2][]byte
	orders := [][]string{{envAPath, envBPath}, {envBPath, envAPath}}
	for i, order := range orders {
		reg, err := registry.Open(filepath.Join(dir, "reg", order[0]+"-first"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range order {
			e := envA
			if p == envBPath {
				e = envB
			}
			if _, _, err := reg.Add(e); err != nil {
				t.Fatalf("add %s: %v", p, err)
			}
		}
		id, _, err := reg.Add(envA) // idempotent; returns the (shared) claim id
		if err != nil {
			t.Fatal(err)
		}
		if got := len(reg.BySigner(kidA)); got != 1 {
			t.Errorf("order %d: by signer A: want 1 claim, got %d", i, got)
		}
		if got := len(reg.BySigner(kidB)); got != 1 {
			t.Errorf("order %d: by signer B: want 1 claim, got %d", i, got)
		}
		rec, ok := reg.Claim(id)
		if !ok {
			t.Fatalf("order %d: claim %s not found", i, id)
		}
		if n := len(rec.Envelope.Signatures); n != 2 {
			t.Errorf("order %d: want 2 unioned signatures, got %d", i, n)
		}
		if ok, _ := rec.Envelope.Verify(pubA); !ok {
			t.Errorf("order %d: signer A does not verify against the unioned envelope", i)
		}
		if ok, _ := rec.Envelope.Verify(pubB); !ok {
			t.Errorf("order %d: signer B does not verify against the unioned envelope", i)
		}
		b, err := os.ReadFile(filepath.Join(dir, "reg", order[0]+"-first", "objects", "sha256", id[len("sha256:"):]+".json"))
		if err != nil {
			t.Fatal(err)
		}
		objBytes[i] = b
	}
	if string(objBytes[0]) != string(objBytes[1]) {
		t.Errorf("stored object is NOT order-independent:\n A-first: %s\n B-first: %s", objBytes[0], objBytes[1])
	}
}
