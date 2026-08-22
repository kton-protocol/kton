package foton

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"kton.dev/plankton/core"
)

func testSpec() Spec {
	return Spec{
		Inputs:   []FileSpec{{Path: "raw/data.csv", Hash: "sha256:" + hex64('a')}},
		Outputs:  []FileSpec{{Path: "out/fit.rds", Hash: "sha256:" + hex64('b')}},
		Protocol: &ProtocolSpec{Kind: "script", Descriptor: map[string]any{"cmd": "Rscript fit.R"}},
	}
}

func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func key(t *testing.T, label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// TestPayloadMatchesTheShapeTheCLIWrote: the refactor moved the assembly, it must not have changed
// it. The expected statement is built here the way cmd/plankton built it before the lift, so this
// fails if the wire form drifts - which would silently give the same foton two ids across versions.
func TestPayloadMatchesTheShapeTheCLIWrote(t *testing.T) {
	spec := testSpec()
	got, err := StatementPayload(spec)
	if err != nil {
		t.Fatalf("StatementPayload: %v", err)
	}
	refBytes, err := core.CanonValue(spec.Protocol.Descriptor)
	if err != nil {
		t.Fatalf("canon descriptor: %v", err)
	}
	want, err := core.CanonValue(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out/fit.rds", "digest": map[string]any{"sha256": hex64('b')}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs": []any{map[string]any{"name": "raw/data.csv", "digest": map[string]any{"sha256": hex64('a')}}},
			"protocol": map[string]any{
				"kind":       "script",
				"ref":        core.HashBytes(refBytes),
				"descriptor": spec.Protocol.Descriptor,
			},
			"specVersion": core.SpecVersion,
		},
	})
	if err != nil {
		t.Fatalf("canon expected: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("payload drifted from the form the CLI wrote:\n got: %s\nwant: %s", got, want)
	}
}

// TestSealRefusesAMismatchedKey: a caller that signed with one key and sealed against another must
// learn here, not when a registry rejects the record much later.
func TestSealRefusesAMismatchedKey(t *testing.T) {
	_, priv := key(t, "signer")
	otherPub, _ := key(t, "someone-else")
	payload, toSign, err := SigningInput(testSpec())
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	if _, _, err := Seal(payload, ed25519.Sign(priv, toSign), otherPub); err == nil {
		t.Error("Seal accepted a signature that does not verify against the supplied key")
	}
}

// TestSealReportsTheIdOfWhatWasSigned: the id Seal returns is recovered from the signed bytes and
// must equal the id computed from the spec - otherwise a caller could be told one identity while
// the registry indexes another.
func TestSealReportsTheIdOfWhatWasSigned(t *testing.T) {
	pub, priv := key(t, "signer")
	spec := testSpec()
	env, id, err := SignWith(spec, priv)
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	want, err := FotonID(spec)
	if err != nil {
		t.Fatalf("FotonID: %v", err)
	}
	if id != want {
		t.Errorf("Seal returned %s, FotonID says %s", id, want)
	}
	if env.Signatures[0].KeyID != core.KeyIDHex(pub) {
		t.Errorf("keyid %s, want %s", env.Signatures[0].KeyID, core.KeyIDHex(pub))
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	var st core.Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("payload not a statement: %v", err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatalf("ToFoton: %v", err)
	}
	if got, _ := f.FotonID(); got != id {
		t.Errorf("the envelope's own bytes yield %s, Seal said %s", got, id)
	}
}

// TestURIIsCarriedNotCovered: a fetch hint locates a file, it does not say what the file IS. Adding
// one must never change the foton's identity (SPEC §6.1) - otherwise recording where bytes live
// would fork the record, and two parties holding the same result under different mirrors would stop
// meeting at a shared id.
func TestURIIsCarriedNotCovered(t *testing.T) {
	bare := testSpec()
	located := testSpec()
	located.Inputs[0].URI = []string{"https://example.org/raw/data.csv"}

	a, err := FotonID(bare)
	if err != nil {
		t.Fatalf("FotonID(bare): %v", err)
	}
	b, err := FotonID(located)
	if err != nil {
		t.Fatalf("FotonID(located): %v", err)
	}
	if a != b {
		t.Errorf("a fetch hint changed the identity: %s vs %s", a, b)
	}
}

// TestProtocolRefIsDerived: `ref` is never accepted from a caller - it is sha256(canon(descriptor)).
// Two different descriptors must not be able to present the same ref.
func TestProtocolRefIsDerived(t *testing.T) {
	one := testSpec()
	two := testSpec()
	two.Protocol.Descriptor = map[string]any{"cmd": "Rscript fit.R", "env": "oci://img@sha256:" + hex64('c')}

	p1, err := StatementPayload(one)
	if err != nil {
		t.Fatalf("one: %v", err)
	}
	p2, err := StatementPayload(two)
	if err != nil {
		t.Fatalf("two: %v", err)
	}
	if string(p1) == string(p2) {
		t.Error("two different protocols produced the same payload")
	}
	id1, _ := FotonID(one)
	id2, _ := FotonID(two)
	if id1 == id2 {
		t.Error("pinning an environment did not change the foton id - the ref is not covering the descriptor")
	}
}

// TestRefusesAnAttestation: plankton records reproducible results; a verdict belongs to nekton.
func TestRefusesAnAttestation(t *testing.T) {
	spec := testSpec()
	spec.Predicate = "reviewed"
	if _, err := StatementPayload(spec); err == nil {
		t.Error("accepted an attestation predicate")
	}
}
