package foton_test

import (
	"crypto/ed25519"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
)

func withClass(stmt string) foton.Spec {
	s := work(stmt, "b.txt", "c.txt", "zusammen.R")
	p := *s.Protocol
	p.Descriptor = map[string]any{"cmd": "Rscript zusammen.R", "environment": h("env-spectrum R 4.3")}
	s.Protocol = &p
	return s
}

// ReadEnv returns a producer's envRef only about this record, only under a key the reader holds that
// also signed the record, and only where the concrete environment is carried at all: foton/v1 with a
// declared class (SPEC §6.5).
func TestEnv_ReadOnlyWhereCarriedAndOnlyFromTheRecordsSigner(t *testing.T) {
	k, other := key("k"), key("other")
	rec, id, err := foton.SignWith(withClass("v1"), k)
	if err != nil {
		t.Fatal(err)
	}
	img := "oci://r@sha256:" + h("image")[7:]
	ok, err := foton.SignEnv(id, img, k)
	if err != nil {
		t.Fatal(err)
	}
	if ran, err := foton.ReadEnv(ok.Scheme, ok.Material, rec, []ed25519.PublicKey{pub(k)}); err != nil || ran.EnvRef != img || ran.Signer != core.KeyIDHex(pub(k)) {
		t.Errorf("a valid env statement: %+v %v", ran, err)
	}
	if _, err := foton.ReadEnv(ok.Scheme, ok.Material, rec, []ed25519.PublicKey{pub(other)}); err == nil {
		t.Error("an env statement signed by a key the reader does not hold was read")
	}
	// Signed by a key the reader trusts, but that key never signed the record.
	stranger, _ := foton.SignEnv(id, img, other)
	if _, err := foton.ReadEnv(stranger.Scheme, stranger.Material, rec, []ed25519.PublicKey{pub(k), pub(other)}); err == nil {
		t.Error("an env statement from a key that did not sign the record was read")
	}
	foreign, _ := foton.SignEnv(h("another record"), img, k)
	if _, err := foton.ReadEnv(foreign.Scheme, foreign.Material, rec, []ed25519.PublicKey{pub(k)}); err == nil {
		t.Error("an env statement about another record was read as this one's")
	}
	if ran, err := foton.ReadEnv(foton.LocatorScheme, ok.Material, rec, nil); ran != nil || err != nil {
		t.Error("material of another scheme is simply not env material")
	}
	if _, err := foton.SignEnv(id, " ", k); err == nil {
		t.Error("an empty envRef was signed")
	}
	// Where the concrete environment is covered - no class, or v0 - a carried one is not read.
	for name, spec := range map[string]foton.Spec{"v1 without a class": work("v1", "b.txt"), "v0 with a class": withClass("")} {
		r, rid, err := foton.SignWith(spec, k)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := foton.SignEnv(rid, img, k)
		if _, err := foton.ReadEnv(m.Scheme, m.Material, r, []ed25519.PublicKey{pub(k)}); err == nil {
			t.Errorf("%s: env material was read", name)
		}
	}
}
