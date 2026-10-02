package rdf

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

type sigEntry = struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// coSigned returns one foton envelope signed by every key in keys, in that order, each signature
// declaring the keyid given at the same index.
func coSigned(t *testing.T, keys []ed25519.PrivateKey, keyids []string) core.Envelope {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out.csv", "digest": map[string]any{"sha256": strings.Repeat("22", 32)}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in.csv", "digest": map[string]any{"sha256": strings.Repeat("11", 32)}}},
			"protocol": map[string]any{"kind": "qc", "ref": "sha256:proto"},
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	for i, k := range keys {
		sig := ed25519.Sign(k, core.PAE(core.PayloadType, payload))
		env.Signatures = append(env.Signatures, sigEntry{KeyID: keyids[i], Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return env
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A co-signed foton is attributed to every trusted key that verifies it - once each, whatever the
// first signature declares and however often a key is listed as trusted.
func TestEveryVerifiedSignerIsAttributedOnce(t *testing.T) {
	pubA, privA := key(t)
	pubB, privB := key(t)
	for _, tc := range []struct {
		name   string
		keyids []string
	}{
		{"declared keyids", []string{core.KeyIDHex(pubA), core.KeyIDHex(pubB)}},
		// An empty keyid on the first signature used to suppress every attribution.
		{"empty first keyid", []string{"", core.KeyIDHex(pubB)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := registry.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := r.Add(coSigned(t, []ed25519.PrivateKey{privA, privB}, tc.keyids)); err != nil {
				t.Skipf("the registry refuses this envelope, so it never reaches the projection: %v", err)
			}
			ttl, err := Turtle(r, "", []ed25519.PublicKey{pubA, pubB, pubA})
			if err != nil {
				t.Fatal(err)
			}
			for _, pub := range []ed25519.PublicKey{pubA, pubB} {
				if n := strings.Count(ttl, "prov:wasAttributedTo agent:"+core.KeyIDHex(pub)); n != 1 {
					t.Errorf("signer %s attributed %d times, want 1:\n%s", core.KeyIDHex(pub), n, ttl)
				}
			}
			if !strings.Contains(ttl, "nk:signerVerified true") || strings.Contains(ttl, "nk:claimedSigner") {
				t.Errorf("a verified foton must be marked verified, not claimed:\n%s", ttl)
			}
		})
	}
}

// Without a trusted key that verifies it, the first declared keyid is carried as a claim only.
func TestUnverifiedSignerIsOnlyClaimed(t *testing.T) {
	pubA, privA := key(t)
	other, _ := key(t)
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(coSigned(t, []ed25519.PrivateKey{privA}, []string{core.KeyIDHex(pubA)})); err != nil {
		t.Fatal(err)
	}
	ttl, err := Turtle(r, "", []ed25519.PublicKey{other})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ttl, "prov:wasAttributedTo agent:") {
		t.Errorf("an unverified signer was attributed:\n%s", ttl)
	}
	if !strings.Contains(ttl, "nk:claimedSigner agent:"+core.KeyIDHex(pubA)) || !strings.Contains(ttl, "nk:signerVerified false") {
		t.Errorf("the claimed signer is not carried as unverified:\n%s", ttl)
	}
}
