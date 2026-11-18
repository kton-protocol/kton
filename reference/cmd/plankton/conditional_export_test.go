package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/rdf"
	"kton.dev/plankton/registry"
)

// A conditional foton carries its mark in the JSON graph and the Turtle export, as it already does in
// the per-record quads (#224); an ordinary foton carries none.
func TestExportsMarkConditionalFotons(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := func(s string) string { return core.HashBytes([]byte(s)) }
	spec := func(out string, conds []core.Condition) foton.Spec {
		return foton.Spec{Statement: "v1",
			Inputs:   []foton.FileSpec{{Path: "in.txt", Hash: h("in")}},
			Outputs:  []foton.FileSpec{{Path: out, Hash: h(out)}},
			Protocol: &foton.ProtocolSpec{Kind: "script", Descriptor: map[string]any{"cmd": "make " + out}, Conditions: conds}}
	}
	var condID string
	for _, s := range []foton.Spec{
		spec("plain.txt", nil),
		spec("fetched.txt", []core.Condition{{Kind: "network", Ref: "https://units.example/convert"}}),
	} {
		env, id, err := foton.SignWith(s, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
		if len(s.Protocol.Conditions) > 0 {
			condID = id
		}
	}
	out := filepath.Join(t.TempDir(), "g.json")
	if err := exportJSON(dir, "t", out, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	var g exportGraph
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	for _, f := range g.Fotons {
		want := f.ID == condID
		if f.Conditional != want || (len(f.Conditions) > 0) != want {
			t.Errorf("JSON foton %s: conditional %v conditions %v, want conditional=%v", f.ID, f.Conditional, f.Conditions, want)
		}
	}
	r2, _ := registry.Open(dir)
	ttl, err := rdf.Turtle(r2, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ttl, "nk:conditional true") != 1 || !strings.Contains(ttl, `nk:condition [ nk:conditionKind "network" ; nk:conditionRef "https://units.example/convert" ]`) {
		t.Errorf("Turtle lacks the conditional mark:\n%s", ttl)
	}
}
