package registry_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// The two questions a consumer asks about reproduction, answered by the registry rather than only by
// a CLI. A consumer that must not take a reproduction level from whoever is asking has to RUN the
// comparison; if the only implementation is a command, every integrator writes a second one - and
// two implementations of an identity rule are two opinions about identity.
func TestReproductionsAndReproduces(t *testing.T) {
	dir := t.TempDir()
	key := func(b byte) ed25519.PrivateKey {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = b
		}
		return ed25519.NewKeyFromSeed(seed)
	}
	privA, privB := key(0x11), key(0x22)
	out := "sha256:" + strings.Repeat("d", 64)

	// Two INDEPENDENT producers of the same output bytes, each with its own inputs - which is what
	// makes them independent rather than one record twice.
	author := func(priv ed25519.PrivateKey, in string) {
		t.Helper()
		spec := foton.Spec{
			Inputs:   []foton.FileSpec{{Path: "in", Hash: "sha256:" + strings.Repeat(in, 64)}},
			Outputs:  []foton.FileSpec{{Path: "out", Hash: out}},
			Protocol: &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"who": in}},
		}
		env, _, err := foton.SignWith(spec, priv)
		if err != nil {
			t.Fatal(err)
		}
		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
	}
	author(privA, "a")
	author(privB, "b")

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("without trusted keys the count is self-declared", func(t *testing.T) {
		got := r.Reproductions(out, nil)
		if got.Verified {
			t.Error("Verified is true with no trusted key - that count is forgeable and must say so")
		}
		if got.DistinctSigners != 2 || got.ProducerFotons != 2 {
			t.Errorf("signers=%d fotons=%d, want 2/2", got.DistinctSigners, got.ProducerFotons)
		}
		for _, p := range got.Producers {
			if p.Verified {
				t.Errorf("producer %s reported verified without a trusted key", p.FotonID)
			}
		}
	})

	t.Run("with one trusted key the other is excluded, not counted", func(t *testing.T) {
		got := r.Reproductions(out, []ed25519.PublicKey{privA.Public().(ed25519.PublicKey)})
		if !got.Verified {
			t.Error("Verified is false although a trusted key was supplied")
		}
		if got.DistinctSigners != 1 {
			t.Errorf("distinct signers = %d, want 1 - only A is trusted", got.DistinctSigners)
		}
		if got.ExcludedUntrusted != 1 {
			t.Errorf("excluded = %d, want 1 - B signed but no trusted key verifies it", got.ExcludedUntrusted)
		}
		for _, p := range got.Producers {
			if !p.Verified {
				t.Errorf("a counted producer is unverified: %+v", p)
			}
		}
	})

	t.Run("L0 is byte identity", func(t *testing.T) {
		got, err := r.Reproduces(out, out, "")
		if err != nil {
			t.Fatal(err)
		}
		if !got.Matches || got.Level != "L0" {
			t.Errorf("got %+v, want an L0 match", got)
		}
	})

	t.Run("different bytes with no normalizer do not match", func(t *testing.T) {
		got, err := r.Reproduces(out, "sha256:"+strings.Repeat("e", 64), "")
		if err != nil {
			t.Fatal(err)
		}
		if got.Matches {
			t.Errorf("got %+v, want no match", got)
		}
	})

	// The rule that has to travel WITH the comparison: equality of two malformed strings is not a
	// reproduction. Leaving it in the CLI would mean a linked caller does not get it.
	t.Run("arguments that are not hashes are refused", func(t *testing.T) {
		for _, bad := range []string{"not-a-hash", "sha256:" + strings.Repeat("a", 63), ""} {
			if _, err := r.Reproduces(bad, bad, ""); err == nil {
				t.Errorf("Reproduces(%q, %q) reported a result; equality of two malformed strings is not one", bad, bad)
			}
		}
	})
}
