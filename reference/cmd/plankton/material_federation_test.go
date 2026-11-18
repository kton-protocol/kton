package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// #225: mirror carries a record's env and locator material; show --trust-keys reads it per signer;
// reuse marks a hit from a record with an environment class as needing qualification.
func TestMaterialTravelsAndIsShown(t *testing.T) {
	src, dst, keys := t.TempDir(), t.TempDir(), t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(filepath.Join(keys, "p.pub"), []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	h := func(s string) string { return core.HashBytes([]byte(s)) }
	class := h("env-class")
	spec := foton.Spec{Statement: "v1",
		Inputs:   []foton.FileSpec{{Path: "in.csv", Hash: h("in")}},
		Outputs:  []foton.FileSpec{{Path: "out.csv", Hash: h("out")}},
		Protocol: &foton.ProtocolSpec{Kind: "script", Descriptor: map[string]any{"cmd": "run", "environment": class}}}
	env, id, err := foton.SignWith(spec, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	envM, err := foton.SignEnv(id, "oci:sha256:"+hex.EncodeToString(make([]byte, 32)), priv)
	if err != nil {
		t.Fatal(err)
	}
	locM, err := foton.SignLocators(id, []foton.FileSpec{{Path: "out.csv", Hash: h("out"), URI: []string{"https://example.org/out.csv"}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []foton.LocatorMaterial{envM, locM} {
		if err := r.AttachMaterial(registry.VerificationMaterial(m)); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PLANKTON_DIR", dst)
	for i := 0; i < 2; i++ { // twice: the second mirror carries nothing new
		if err := run("mirror", []string{src}); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := registry.Open(dst)
	if n := len(d.Material(id)); n != 2 {
		t.Fatalf("after mirror the peer holds %d material attachment(s), want 2", n)
	}

	out := captureStdout(t, func() {
		if err := run("show", []string{id, "--json", "--trust-keys", keys}); err != nil {
			t.Fatal(err)
		}
	})
	var got struct {
		Carried carried `json:"carried"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !got.Carried.Checked || len(got.Carried.Environments) != 1 || len(got.Carried.Locators) != 1 {
		t.Errorf("show carried = %+v, want one environment and one locator", got.Carried)
	}

	hits := d.ReuseHits(mustActionKey(t, env))
	if len(hits) != 1 || hits[0].Qualification != "required" || hits[0].EnvClass != class {
		t.Errorf("reuse hits = %+v, want qualification required for class %s", hits, class)
	}
}

func mustActionKey(t *testing.T, env core.Envelope) string {
	t.Helper()
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := f.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	return ak
}
