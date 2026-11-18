package rdf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// The protocol descriptor is carried whole, as one canonical-JSON literal, in both projections
// (#240); a foton without a descriptor carries none. A hostile command stays inside its literal.
func TestDescriptorIsOneLiteral(t *testing.T) {
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte("k"))
	k := ed25519.NewKeyFromSeed(s[:])
	cmd := "Rscript fit.R \"x\"\n<https://evil/x> <https://evil/y> <https://evil/z> ."
	env, id, err := foton.SignWith(foton.Spec{Statement: "v1",
		Inputs:   []foton.FileSpec{{Path: "in.csv", Hash: core.HashBytes([]byte("i"))}},
		Outputs:  []foton.FileSpec{{Path: "out.csv", Hash: core.HashBytes([]byte("o"))}},
		Protocol: &foton.ProtocolSpec{Kind: "run", Descriptor: map[string]any{"cmd": cmd}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	own, err := Record(r, id)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := core.CanonValue(map[string]any{"cmd": cmd})
	if !strings.Contains(string(own), "<https://kton.dev/v/protocolDescriptor> "+nqLiteral(string(want))) {
		t.Errorf("Record lacks the descriptor literal:\n%s", own)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(own)), "\n") {
		if strings.HasPrefix(l, "<https://evil") {
			t.Errorf("the command broke out of its literal: %s", l)
		}
	}
	ttl, err := Turtle(r, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ttl, "nk:protocolDescriptor "+rdfLiteral(string(want))) {
		t.Errorf("Turtle lacks the descriptor literal:\n%s", ttl)
	}

	bare := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "o", "digest": map[string]any{"sha256": strings.Repeat("22", 32)}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "i", "digest": map[string]any{"sha256": strings.Repeat("11", 32)}}},
			"protocol": map[string]any{"kind": "run", "ref": "sha256:" + strings.Repeat("aa", 32)},
		},
	}
	payload, _ := core.CanonValue(bare)
	benv := core.Envelope{PayloadType: core.PayloadType, Payload: b64(payload)}
	benv.Signatures = append(benv.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(k.Public().(ed25519.PublicKey)), b64(ed25519.Sign(k, core.PAE(core.PayloadType, payload)))})
	bid, _, err := r.Add(benv)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := Record(r, bid); strings.Contains(string(b), "protocolDescriptor") {
		t.Errorf("a foton without a descriptor carries one:\n%s", b)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
