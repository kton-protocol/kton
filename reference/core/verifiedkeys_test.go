package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"
)

// VerifiedKeys gives exactly the per-key answer of Verify, over hinted, unhinted, mis-hinted, forged-
// hint, co-signed and untrusted-signer envelopes, with a key listed twice among the trusted ones (#247).
func TestVerifiedKeysEqualsVerifyPerKey(t *testing.T) {
	key := func(i int) ed25519.PrivateKey {
		s := sha256.Sum256([]byte(fmt.Sprint("k", i)))
		return ed25519.NewKeyFromSeed(s[:])
	}
	privs := make([]ed25519.PrivateKey, 6)
	for i := range privs {
		privs[i] = key(i)
	}
	pub := func(i int) ed25519.PublicKey { return privs[i].Public().(ed25519.PublicKey) }
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	msg := PAE(PayloadType, payload)
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 400; round++ {
		env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		for n := 1 + rng.Intn(3); n > 0; n-- {
			signer := rng.Intn(len(privs))
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(privs[signer], msg))
			hint := KeyIDHex(pub(signer))
			switch rng.Intn(5) {
			case 0:
				hint = "" // unhinted
			case 1:
				hint = KeyIDHex(pub(rng.Intn(len(privs)))) // mis-hinted (maybe right by chance)
			case 2:
				hint = "0000000000000000" // names no key
			case 3:
				sig = base64.StdEncoding.EncodeToString(make([]byte, 64)) // a forgery under the right hint
			}
			env.Signatures = append(env.Signatures, struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			}{KeyID: hint, Sig: sig})
		}
		var trusted []ed25519.PublicKey
		for i := 0; i < len(privs)-1; i++ { // the last key is never trusted
			if rng.Intn(2) == 0 {
				trusted = append(trusted, pub(i))
			}
		}
		if len(trusted) > 0 && rng.Intn(3) == 0 {
			trusted = append(trusted, trusted[0]) // a key listed twice
		}
		got := VerifiedKeys(env, trusted)
		for i, k := range trusted {
			ok, err := env.Verify(k)
			if want := ok && err == nil; got[i] != want {
				t.Fatalf("round %d key %d: VerifiedKeys %v, Verify %v (%+v)", round, i, got[i], want, env.Signatures)
			}
		}
	}
}
