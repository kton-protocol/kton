package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// --env-ref is COVERED unless a class is declared on foton/v1 (#211, SPEC §6.5). These are the
// regression cases for both halves:
//   - without --environment, the concrete environment is the only statement of what ran, and a
//     different envRef MUST give a different action key - otherwise two computations collide on one
//     cache key through an undeclared environment;
//   - with --environment on v1, the class is what is covered: a different image of the same class
//     gives the same action key and the same record, and each producer's envRef travels beside it.
func TestEnvRefCoveredUnlessAClassIsDeclared(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	for p, b := range map[string]string{in: "a", out: "b"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, n := range []string{"a", "c"} {
		if err := keygen([]string{filepath.Join(dir, n), "--seed", strings.Repeat(string("5c"[i])+"a", 32)}); err != nil {
			t.Fatal(err)
		}
	}
	class := core.HashBytes([]byte("env-spectrum: R 4.3 on linux/amd64"))
	n := 0
	author := func(reg, key, envRef string, extra ...string) (core.Envelope, string) {
		t.Helper()
		n++
		env := filepath.Join(dir, "f"+string(rune('0'+n))+".dsse.json")
		args := append([]string{"--cmd", "Rscript fit.R", "--in", in, "--out", out, "--env-ref", envRef,
			"--sign", filepath.Join(dir, key+".key"), "-o", env, "--registry", filepath.Join(dir, reg)}, extra...)
		if err := run("author", args); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(env)
		if err != nil {
			t.Fatal(err)
		}
		var e core.Envelope
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		st, err := e.Statement()
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
		return e, ak
	}
	imgA, imgB := "oci://r@sha256:"+strings.Repeat("a", 64), "oci://r@sha256:"+strings.Repeat("b", 64)

	for _, stmt := range []string{"v0", "v1"} {
		_, a := author("x-"+stmt, "a", imgA, "--statement", stmt)
		_, b := author("x-"+stmt, "a", imgB, "--statement", stmt)
		if a == b {
			t.Errorf("%s without a class: two envRefs share an action key", stmt)
		}
	}
	_, a0 := author("y", "a", imgA, "--environment", class)
	_, b0 := author("y", "a", imgB, "--environment", class)
	if a0 == b0 {
		t.Error("v0 with a class: envRef is no longer covered; v0 has no place for carried material")
	}

	if err := run("author", []string{"--statement", "v1", "--environment", class, "--env-ref", imgA, "--cmd", "Rscript fit.R",
		"--in", in, "--out", out, "--sign", filepath.Join(dir, "a.key"), "-o", filepath.Join(dir, "nope.json")}); err == nil {
		t.Error("a carried envRef without --add was accepted; it would be lost")
	}
	_, ak1 := author("z", "a", imgA, "--statement", "v1", "--environment", class, "--add")
	envB, ak2 := author("z", "c", imgB, "--statement", "v1", "--environment", class, "--add")
	if ak1 != ak2 {
		t.Fatal("v1 with a class: two images of the class give two action keys")
	}

	r, err := registry.Open(filepath.Join(dir, "z"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("two producers in two images of one class made %d records, want 1", r.Len())
	}
	st, _ := envB.Statement()
	f, _ := st.ToFoton()
	id, _ := f.FotonID()
	if _, ok := f.Protocol.Descriptor["envRef"]; ok {
		t.Error("a carried envRef is still in the descriptor")
	}
	pubOf := func(n string) ed25519.PublicKey {
		b, _ := os.ReadFile(filepath.Join(dir, n+".pub"))
		raw, _ := hex.DecodeString(strings.TrimSpace(string(b)))
		return ed25519.PublicKey(raw)
	}
	got := map[string]string{}
	for _, m := range r.Material(id) {
		for _, k := range []string{"a", "c"} {
			if ran, err := foton.ReadEnv(m.Scheme, m.Material, *f, []ed25519.PublicKey{pubOf(k)}); err == nil && ran != nil {
				got[k] = ran.EnvRef
			}
		}
	}
	if got["a"] != imgA || got["c"] != imgB {
		t.Errorf("each producer's envRef, under its own key: got %v", got)
	}
	env, _ := r.Envelope(id)
	for _, k := range []string{"a", "c"} {
		if ok, err := env.Verify(pubOf(k)); !ok || err != nil {
			t.Errorf("producer %s's signature is not on the one record", k)
		}
	}
}
