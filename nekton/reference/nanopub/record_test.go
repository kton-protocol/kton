package nanopub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

func seedKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

// A claim's own quads depend on the claim alone: no key, no attribution, no envelope signature. Its
// attribution comes back per verifying key, in a graph of its own (#232).
func TestRecordIsKeylessAndAttributionIsPerKey(t *testing.T) {
	signer, other := seedKey("reviewer"), seedKey("stranger")
	env, id, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{Hash: "sha256:" + strings.Repeat("a", 64)}},
		Predicate: "https://kton.dev/v/reviewed", By: "reviewer", When: "2026-10-21T00:00:00Z",
		Object: map[string]any{"verdict": "ok"},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	c := NewContext(template.Set{}, []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)})
	own, err := Record(c, env)
	if err != nil {
		t.Fatal(err)
	}
	keyless, _ := Record(NewContext(template.Set{}, nil), env)
	if string(own) != string(keyless) {
		t.Error("the own quads depend on the context's trusted keys")
	}
	for _, bad := range []string{"wasAttributedTo", "signerVerified", "claimedSigner", "createdBy", "dc/terms/creator", "dsseSignature", "/keyid>", "npx/hasSignature", "TEMP."} {
		if strings.Contains(string(own), bad) {
			t.Errorf("own quads carry %s:\n%s", bad, own)
		}
	}
	base := RecordBase(id)
	for _, want := range []string{"<" + base + "#assertion>", "<" + base + "#pubinfo>", "<https://kton.dev/v/reviewed>", `"ok"`} {
		if !strings.Contains(string(own), want) {
			t.Errorf("own quads lack %s:\n%s", want, own)
		}
	}

	spub, opub := signer.Public().(ed25519.PublicKey), other.Public().(ed25519.PublicKey)
	att, err := Attribution(c, env, []ed25519.PublicKey{opub, spub, spub})
	if err != nil {
		t.Fatal(err)
	}
	kid := core.KeyIDHex(spub)
	if len(att) != 1 || att[kid] == nil {
		t.Fatalf("attribution keys %v, want only %s", keysOf(att), kid)
	}
	g := "<" + AttributionGraph(id, kid) + ">"
	for _, l := range strings.Split(strings.TrimSpace(string(att[kid])), "\n") {
		if !strings.HasSuffix(l, g+" .") {
			t.Errorf("attribution quad outside its graph: %s", l)
		}
	}
	if !strings.Contains(string(att[kid]), "prov#wasAttributedTo> <https://kton.dev/agent/"+kid+">") {
		t.Errorf("no attribution to the verifying key:\n%s", att[kid])
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
