package main

// What a verifier must get right, and what the two surfaces it replaces got wrong for this purpose:
// the reported signer is the key that ACTUALLY verified (never the envelope's own claim about it),
// every signature is tried (not just the first), and the id is re-derived from the payload.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

func verifyKey(t *testing.T, n byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func aClaim(t *testing.T, priv ed25519.PrivateKey) (core.Envelope, string) {
	t.Helper()
	spec := claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:thing:1"}},
		Predicate: "https://kton.dev/v/note",
		By:        "tester",
		When:      "2026-08-14T10:00:00Z",
	}
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return env, id
}

func doVerify(t *testing.T, env core.Envelope, pubHex string) verifyResult {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	out, err := Verify(string(b), pubHex)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var res verifyResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res
}

func TestVerifyGoodClaim(t *testing.T) {
	priv, pubHex := verifyKey(t, 1)
	env, id := aClaim(t, priv)

	res := doVerify(t, env, pubHex)

	if !res.OK || res.Kind != "claim" {
		t.Fatalf("res = %+v, want ok claim", res)
	}
	if res.ClaimID != id {
		t.Fatalf("claimId = %s, want the id the signer computed %s", res.ClaimID, id)
	}
	if res.Keyid != core.KeyIDHex(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("keyid = %s, want the verifying key's", res.Keyid)
	}
	if res.KeyidMismatch {
		t.Fatal("mismatch flagged on an honest envelope")
	}
	// The statement must be the bytes that were verified, not a re-serialization.
	pb, _ := env.PayloadBytes()
	if string(res.Statement) != string(pb) {
		t.Fatal("statement is not the payload that was verified")
	}
}

// A well-formed record that this key did not sign is a VERDICT (ok:false), not an error - a cockpit
// must be able to tell "not signed by this key" from "this is not a record".
func TestWrongKeyIsAVerdictNotAnError(t *testing.T) {
	priv, _ := verifyKey(t, 2)
	_, otherPub := verifyKey(t, 3)
	env, _ := aClaim(t, priv)

	res := doVerify(t, env, otherPub)

	if res.OK {
		t.Fatal("verified against a key that did not sign it")
	}
	if res.Keyid != "" {
		t.Fatalf("keyid = %q on a failed verify; there is no signer to name", res.Keyid)
	}
	if res.ClaimID == "" {
		t.Fatal("no claim id: a caller still needs to know WHICH record failed")
	}
}

// SPEC §8: the envelope's keyid is not covered by the signature. A forged one must neither be
// believed nor pass unremarked.
func TestForgedDeclaredKeyidIsFlaggedNotBelieved(t *testing.T) {
	priv, pubHex := verifyKey(t, 4)
	env, _ := aClaim(t, priv)
	real := env.Signatures[0].KeyID
	env.Signatures[0].KeyID = "deadbeefdeadbeef" // the lie

	res := doVerify(t, env, pubHex)

	if !res.OK {
		t.Fatal("a forged keyid broke verification; the signature itself is untouched")
	}
	if res.Keyid != real {
		t.Fatalf("keyid = %s, want the VERIFYING key %s, never the declared one", res.Keyid, real)
	}
	if !res.KeyidMismatch || res.DeclaredKeyid != "deadbeefdeadbeef" {
		t.Fatalf("res = %+v, want the mismatch surfaced with the declared value", res)
	}
}

// #16's sibling: a co-signed envelope whose FIRST signature is foreign must still verify for us and
// be attributed to our key. Checking only Signatures[0] under-reports it as unverified.
func TestCoSignedEnvelopeVerifiesOnANonFirstSignature(t *testing.T) {
	mine, minePub := verifyKey(t, 5)
	foreign, _ := verifyKey(t, 6)
	env, _ := aClaim(t, mine)

	// Rebuild as [foreign, mine] over the identical payload. The signatures list is an anonymous
	// struct on core.Envelope, so this goes through the wire form - which is what a cockpit receives
	// anyway.
	pb, _ := env.PayloadBytes()
	foreignSig := ed25519.Sign(foreign, core.PAE(env.PayloadType, pb))
	b, _ := json.Marshal(env)
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	sigs := wire["signatures"].([]any)
	wire["signatures"] = append([]any{map[string]any{
		"keyid": core.KeyIDHex(foreign.Public().(ed25519.PublicKey)),
		"sig":   base64.StdEncoding.EncodeToString(foreignSig),
	}}, sigs...)
	cosigned, _ := json.Marshal(wire)

	out, err := Verify(string(cosigned), minePub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var res verifyResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !res.OK {
		t.Fatal("co-signed envelope read as unverified: only the first signature was checked")
	}
	if res.Keyid != core.KeyIDHex(mine.Public().(ed25519.PublicKey)) {
		t.Fatalf("keyid = %s, want OUR key - the one that verified", res.Keyid)
	}
	if !res.KeyidMismatch {
		t.Fatal("declared keyid is the foreign co-signer's and differs from the verifying one; want it flagged")
	}
}

// The id must come from the payload. A sender who ships a real claim under a borrowed id must not be
// able to get that id echoed back as established.
func TestIDIsDerivedNotEchoed(t *testing.T) {
	priv, pubHex := verifyKey(t, 7)
	env, id := aClaim(t, priv)

	// There is nowhere in the envelope to state an id - which is the point - so assert the derived
	// value against an independent computation of the rule.
	pb, _ := env.PayloadBytes()
	res := doVerify(t, env, pubHex)
	if res.ClaimID != claim.ClaimID(pb) || res.ClaimID != id {
		t.Fatalf("claimId = %s, want the payload-derived %s", res.ClaimID, claim.ClaimID(pb))
	}
}

// A seed is a claim-id payload too, but a cockpit needs to know it opens a scope.
func TestSeedIsReportedAsASeed(t *testing.T) {
	priv, pubHex := verifyKey(t, 8)
	spec := claim.Spec{
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "s", "responsible": []any{"tester"}, "genesis": true},
	}
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("sign seed: %v", err)
	}

	res := doVerify(t, env, pubHex)

	if !res.OK || res.Kind != "seed" || res.ClaimID != id {
		t.Fatalf("res = %+v, want an ok seed with id %s", res, id)
	}
}

// A foton's identity is its FOTON id (a hash of the covered projection), not the payload hash. A
// cockpit taking in foreign entries receives these too, and keying one on the wrong rule would file
// it under an id nobody else uses.
func TestFotonIsIdentifiedByItsFotonID(t *testing.T) {
	priv, pubHex := verifyKey(t, 11)
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"out.csv","digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}],` +
		`"predicateType":"https://kton.dev/foton/v0",` +
		`"predicate":{"inputs":[{"name":"in.csv","digest":{"sha256":"` + strings.Repeat("cd", 32) + `"}}],` +
		`"protocol":{"kind":"run","ref":"sha256:` + strings.Repeat("ef", 32) + `"}}}`)
	env := signedEnvelope(t, priv, stmt)

	res := doVerify(t, env, pubHex)

	if !res.OK || res.Kind != "foton" {
		t.Fatalf("res = %+v, want an ok foton", res)
	}
	if res.ClaimID != "" {
		t.Fatalf("claimId = %s set on a foton; only the foton id governs it", res.ClaimID)
	}
	st, _ := env.Statement()
	f, _ := st.ToFoton()
	want, _ := f.FotonID()
	if res.FotonID != want {
		t.Fatalf("fotonId = %s, want the covered-projection id %s", res.FotonID, want)
	}
}

// signedEnvelope wraps raw statement bytes in a DSSE envelope signed by priv.
func signedEnvelope(t *testing.T, priv ed25519.PrivateKey, stmt []byte) core.Envelope {
	t.Helper()
	pt := core.PayloadType
	sig := ed25519.Sign(priv, core.PAE(pt, stmt))
	wire := map[string]any{
		"payloadType": pt,
		"payload":     base64.StdEncoding.EncodeToString(stmt),
		"signatures": []any{map[string]any{
			"keyid": core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	b, _ := json.Marshal(wire)
	var env core.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	return env
}

// Garbage in must be an ERROR, not a confident ok:false - the caller is being told the input is not
// a record at all.
func TestNonEnvelopeIsAnError(t *testing.T) {
	_, pubHex := verifyKey(t, 9)
	if _, err := Verify(`{"not":"an envelope"}`, pubHex); err == nil {
		t.Fatal("an envelope with no payload verified as readable")
	}
	if _, err := Verify(`not json at all`, pubHex); err == nil {
		t.Fatal("non-JSON accepted")
	}
	env, _ := aClaim(t, mustKey(t))
	b, _ := json.Marshal(env)
	if _, err := Verify(string(b), "not-a-key"); err == nil {
		t.Fatal("a malformed public key was accepted")
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, _ := verifyKey(t, 10)
	return priv
}
