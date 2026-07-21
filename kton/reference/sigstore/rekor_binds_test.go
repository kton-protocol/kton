package sigstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"kton.dev/plankton/core"
)

func verifierPEMFor(pub ed25519.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// synth builds a Rekor `dsse` entry Body (base64) with the given payload hash + verifier.
func synthBody(payloadHashHex string, verifierPEM []byte) string {
	m := map[string]any{"kind": "dsse", "apiVersion": "0.0.1", "spec": map[string]any{
		"payloadHash": map[string]any{"algorithm": "sha256", "value": payloadHashHex},
		"signatures":  []any{map[string]any{"verifier": base64.StdEncoding.EncodeToString(verifierPEM)}},
	}}
	b, _ := json.Marshal(m)
	return base64.StdEncoding.EncodeToString(b)
}

func TestVerifyBinds(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	vpem := verifierPEMFor(pub)
	payload := []byte(`{"_type":"x","subject":[]}`)
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	sum := sha256.Sum256(payload)

	// genuine entry for THIS record -> binds
	e := &Entry{Body: synthBody(hex.EncodeToString(sum[:]), vpem)}
	if err := e.VerifyBinds(env, vpem); err != nil {
		t.Fatalf("a matching entry must bind: %v", err)
	}
	// replayed entry for a DIFFERENT payload -> rejected
	other := sha256.Sum256([]byte("some other record"))
	e2 := &Entry{Body: synthBody(hex.EncodeToString(other[:]), vpem)}
	if err := e2.VerifyBinds(env, vpem); err == nil {
		t.Error("an entry about a different payload must be rejected (replay)")
	}
	// right payload but a DIFFERENT verifier key -> rejected
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	e3 := &Entry{Body: synthBody(hex.EncodeToString(sum[:]), verifierPEMFor(pub2))}
	if err := e3.VerifyBinds(env, vpem); err == nil {
		t.Error("an entry carrying a different verifier must be rejected")
	}
}
