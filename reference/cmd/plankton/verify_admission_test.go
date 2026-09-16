package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// sign wraps payload in a DSSE envelope signed for real, so neither reproduction can be dismissed as
// "well, it wasn't properly signed". Both records below are genuine; what they are not is storable.
func sign(t *testing.T, payload []byte) core.Envelope {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := core.Envelope{
		PayloadType: core.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
	}
	sig := ed25519.Sign(priv, core.PAE(env.PayloadType, payload))
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	})
	return env
}

// TestVerifyAgreesWithIngest is the whole point of sharing the admission gate: `verify` prints
//
//	structure:       VALID - the record is one this store would accept
//
// and that sentence is a claim about `Add`. It was false for two genuinely signed records, because
// verify kept its own shorter list of rules - it returned success immediately for any non-foton
// predicate and never computed the action key.
//
// So this test does not assert that verify refuses. It asserts that verify and Add AGREE, in both
// directions, which is the property that cannot silently rot: a rule added to one and not the other
// fails here.
func TestVerifyAgreesWithIngest(t *testing.T) {
	canon := func(v any) []byte {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		c, err := core.CanonJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	h := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

	cases := []struct {
		name    string
		payload []byte
		why     string
	}{
		{
			// The issue's second reproduction: a valid in-toto Statement that is not a foton.
			// verify returned nil for it without looking at anything, so it printed the
			// store-admission verdict for a record Add refuses with ErrNotFoton.
			name: "a signed non-foton statement",
			payload: canon(map[string]any{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://example.org/something-else/v1",
				"subject":       []any{map[string]any{"digest": map[string]any{"sha256": strings.Repeat("a", 64)}}},
				"predicate":     map[string]any{"note": "not a foton"},
			}),
			why: "Add refuses it with ErrNotFoton",
		},
		{
			// The issue's first reproduction: two inputs at one relative path with DIFFERENT
			// hashes. The {path -> hash} map can hold only one, so an input would vanish from the
			// computation's identity - and a 2-input foton could falsely reuse a 1-input result.
			name: "a foton whose action key is ambiguous",
			payload: canon(map[string]any{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": core.PredicateFoton,
				"subject": []any{map[string]any{
					"name": "out.csv", "digest": map[string]any{"sha256": strings.Repeat("c", 64)},
				}},
				"predicate": map[string]any{
					"inputs": []any{
						map[string]any{"name": "in", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}},
						map[string]any{"name": "in", "digest": map[string]any{"sha256": strings.Repeat("b", 64)}},
					},
					"protocol": map[string]any{"kind": "script", "ref": h('d')},
				},
			}),
			why: "Add refuses it: the action key is ambiguous",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sign(t, tc.payload)

			// It really is signed. If this fails the reproduction proves nothing.
			if !env.HasSignature() {
				t.Fatal("the fixture is unsigned")
			}

			verr := verifyStructure(env)
			r, err := registry.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			_, _, aerr := r.Add(env)

			if aerr == nil {
				t.Fatalf("Add accepted this record, so the premise is wrong (%s)", tc.why)
			}
			if verr == nil {
				t.Fatalf("verify printed the store-admission verdict for a record Add refuses: %v", aerr)
			}
			// Agreement is not just "both non-nil": ErrNotFoton must survive to the caller, because
			// a non-foton is a different answer from a malformed foton.
			if errors.Is(aerr, registry.ErrNotFoton) != errors.Is(verr, registry.ErrNotFoton) {
				t.Errorf("verify and Add disagree about WHY: verify=%v add=%v", verr, aerr)
			}
		})
	}

	// The other direction, and the one that matters most today: an ordinary valid foton must still
	// pass both. A gate that refuses the normal path is the failure this repository keeps finding.
	t.Run("an ordinary foton still passes both", func(t *testing.T) {
		desc := map[string]any{"cmd": "cp in.csv out.csv"}
		ref, err := core.ComputeProtocolRef(desc)
		if err != nil {
			t.Fatal(err)
		}
		payload := canon(map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"predicateType": core.PredicateFoton,
			"subject": []any{map[string]any{
				"name": "out.csv", "digest": map[string]any{"sha256": strings.Repeat("c", 64)},
			}},
			"predicate": map[string]any{
				"inputs": []any{map[string]any{
					"name": "in.csv", "digest": map[string]any{"sha256": strings.Repeat("a", 64)},
				}},
				"protocol": map[string]any{"kind": "script", "ref": ref, "descriptor": desc},
			},
		})
		env := sign(t, payload)
		if err := verifyStructure(env); err != nil {
			t.Errorf("verify refused an ordinary foton: %v", err)
		}
		r, err := registry.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Errorf("Add refused an ordinary foton: %v", err)
		}
	})
}
