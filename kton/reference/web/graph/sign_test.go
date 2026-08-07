package main

// The property that matters: a claim authored the BROWSER way (BuildClaim -> external signer ->
// SealClaim) must be byte-identical to the same claim authored the CLI way (claim.SignWith).
// If these ever diverge, the two produce different claim ids and stop deduplicating in a
// federated union - the exact failure the shared claim/spec.go exists to prevent.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

const specJSON = `{
  "subject":   [{"hash":"sha256:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788AA"}],
  "predicate": "https://w3id.org/security#controller",
  "object":    {"id":"https://orcid.org/0000-0002-1825-0097"},
  "by":        "https://openscience.local",
  "when":      "2026-08-07T10:00:00Z"
}`

// deterministic key so failures are reproducible
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestBrowserPathMatchesCLIPath(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)

	// --- the browser path -------------------------------------------------
	built, err := BuildClaim(specJSON)
	if err != nil {
		t.Fatalf("BuildClaim: %v", err)
	}
	toSign, err := base64.StdEncoding.DecodeString(built["toSign"].(string))
	if err != nil {
		t.Fatalf("toSign not base64: %v", err)
	}
	// stands in for crypto.subtle.sign over the non-extractable key
	sig := ed25519.Sign(priv, toSign)
	sealed, err := SealClaim(built["payload"].(string), base64.StdEncoding.EncodeToString(sig), pubHex)
	if err != nil {
		t.Fatalf("SealClaim: %v", err)
	}

	// --- the CLI path -----------------------------------------------------
	spec, err := claim.ParseSpec([]byte(specJSON))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	cliEnv, cliID, err := claim.SignWith(spec, priv)
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}

	if sealed["claimId"] != cliID {
		t.Errorf("claim id differs:\n browser %v\n cli     %v", sealed["claimId"], cliID)
	}

	var rec struct {
		ClaimID  string `json:"claimId"`
		Envelope struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			} `json:"signatures"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal([]byte(sealed["record"].(string)), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	if rec.Envelope.Payload != cliEnv.Payload {
		t.Error("signed payload differs between browser and CLI paths")
	}
	if rec.Envelope.PayloadType != cliEnv.PayloadType {
		t.Errorf("payloadType differs: %q vs %q", rec.Envelope.PayloadType, cliEnv.PayloadType)
	}
	if len(rec.Envelope.Signatures) != 1 || rec.Envelope.Signatures[0].KeyID != cliEnv.Signatures[0].KeyID {
		t.Error("keyid differs between browser and CLI paths")
	}
	// Ed25519 is deterministic, so even the signature bytes must match.
	if rec.Envelope.Signatures[0].Sig != cliEnv.Signatures[0].Sig {
		t.Error("signature bytes differ between browser and CLI paths")
	}
}

// A signature made with the wrong key must be refused at seal time, in the browser, rather than
// producing a record that a registry silently rejects later.
func TestSealRejectsWrongKey(t *testing.T) {
	priv := testKey(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	built, err := BuildClaim(specJSON)
	if err != nil {
		t.Fatalf("BuildClaim: %v", err)
	}
	toSign, _ := base64.StdEncoding.DecodeString(built["toSign"].(string))
	sig := ed25519.Sign(priv, toSign)

	_, err = SealClaim(built["payload"].(string), base64.StdEncoding.EncodeToString(sig), hex.EncodeToString(other))
	if err == nil {
		t.Fatal("expected SealClaim to reject a signature that does not verify against the given key")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("unhelpful error for key mismatch: %v", err)
	}
}

func TestKeyIRIIsFullHashAndStable(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	iri, err := KeyIRI(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("KeyIRI: %v", err)
	}
	// Full sha256 (64 hex), not the 16-hex display keyid - the IRI must not be collidable.
	rest, ok := strings.CutPrefix(iri, "https://kton.dev/o/")
	if !ok {
		t.Fatalf("unexpected IRI form: %s", iri)
	}
	if len(rest) != 64 {
		t.Errorf("expected a full 64-hex sha256 in the key IRI, got %d chars: %s", len(rest), rest)
	}
	if _, err := KeyIRI("not-hex"); err == nil {
		t.Error("expected KeyIRI to reject a non-hex key")
	}
}
