package foton_test

import (
	"crypto/ed25519"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
)

// ReadEnv returns a producer's envRef only for this record and only under a key the reader holds.
func TestEnv_OnlyThisRecordAndOnlyGivenKeys(t *testing.T) {
	k, other := key("k"), key("other")
	env, id, err := foton.SignWith(work("v1", "b.txt", "c.txt", "zusammen.R"), k)
	if err != nil {
		t.Fatal(err)
	}
	f := recordOfEnv(t, env)
	img := "oci://r@sha256:" + h("image")[7:]

	ok, err := foton.SignEnv(id, img, k)
	if err != nil {
		t.Fatal(err)
	}
	if ran, err := foton.ReadEnv(ok.Scheme, ok.Material, f, []ed25519.PublicKey{pub(k)}); err != nil || ran.EnvRef != img || ran.Signer != core.KeyIDHex(pub(k)) {
		t.Errorf("a valid env statement: %+v %v", ran, err)
	}
	if _, err := foton.ReadEnv(ok.Scheme, ok.Material, f, []ed25519.PublicKey{pub(other)}); err == nil {
		t.Error("an env statement signed by a key the reader does not hold was read")
	}
	foreign, _ := foton.SignEnv(h("another record"), img, k)
	if _, err := foton.ReadEnv(foreign.Scheme, foreign.Material, f, []ed25519.PublicKey{pub(k)}); err == nil {
		t.Error("an env statement about another record was read as this one's")
	}
	if ran, err := foton.ReadEnv(foton.LocatorScheme, ok.Material, f, nil); ran != nil || err != nil {
		t.Error("material of another scheme is simply not env material")
	}
	if _, err := foton.SignEnv(id, " ", k); err == nil {
		t.Error("an empty envRef was signed")
	}
}

func recordOfEnv(t *testing.T, env core.Envelope) core.Foton {
	t.Helper()
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	return *f
}
