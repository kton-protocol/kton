package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

// The issue's measured case: 7 trusted keys, one hinted signature (#247).
func benchEnv(b *testing.B) (Envelope, []ed25519.PublicKey) {
	var keys []ed25519.PublicKey
	var privs []ed25519.PrivateKey
	for i := 0; i < 7; i++ {
		s := sha256.Sum256([]byte(fmt.Sprint("b", i)))
		p := ed25519.NewKeyFromSeed(s[:])
		privs = append(privs, p)
		keys = append(keys, p.Public().(ed25519.PublicKey))
	}
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyIDHex(keys[3]), base64.StdEncoding.EncodeToString(ed25519.Sign(privs[3], PAE(PayloadType, payload)))})
	return env, keys
}

func BenchmarkVerifyPerKey(b *testing.B) {
	env, keys := benchEnv(b)
	for i := 0; i < b.N; i++ {
		for _, k := range keys {
			env.Verify(k)
		}
	}
}

func BenchmarkVerifiedKeys(b *testing.B) {
	env, keys := benchEnv(b)
	for i := 0; i < b.N; i++ {
		VerifiedKeys(env, keys)
	}
}
