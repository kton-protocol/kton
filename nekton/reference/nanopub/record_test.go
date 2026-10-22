package nanopub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"regexp"
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

// Review of #235: an unsigned envelope is refused (R1). On the record path a value is an IRI only if
// it is one, a bad content hash is a literal, and no control character reaches a line raw (R2).
func TestRecordTermRuleIsStrict(t *testing.T) {
	c := NewRecordContext(template.Set{})
	if _, err := Record(c, core.Envelope{Payload: "e30="}); err == nil {
		t.Error("an unsigned envelope was projected")
	}
	env, _, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{Hash: "sha256:" + strings.Repeat("a", 64)}},
		Predicate: "https://kton.dev/v/reviewed", By: "rev\x00iewer\u2028", When: "2026-10-21T00:00:00Z",
		Object: map[string]any{
			"note": "see https://x.org for details", "ref": "sha256:zz> <https://evil/x", "ctl": "a\x0bb",
			"link": "https://example.org/a b\u2028c", "ok": "sha256:" + strings.Repeat("b", 64),
		},
	}, seedKey("reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	own, err := Record(c, env)
	if err != nil {
		t.Fatal(err)
	}
	text := string(own)
	// Not IRIs, so literals: free text with a URL in it, a bad content hash, a URL with a space.
	for _, want := range []string{`"see https://x.org for details"`, `"sha256:zz> <https://evil/x"`, `"a\u000Bb"`,
		`"https://example.org/a b\u2028c"`, "<https://kton.dev/o/" + strings.Repeat("b", 64) + ">"} {
		if !strings.Contains(text, want) {
			t.Errorf("own quads lack %s:\n%s", want, text)
		}
	}
	if strings.ContainsAny(text, "\x00\x0b\u0085\u2028\u2029") || len(strings.Split(strings.TrimSpace(text), "\n")) != strings.Count(text, " .\n") {
		t.Errorf("a raw control character reached the output:\n%s", text)
	}
	// No IRI term carries a character a parser rejects, and none was made from the hostile values.
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		for _, m := range regexp.MustCompile(`<[^>]*>`).FindAllString(strings.SplitN(l, "\"", 2)[0], -1) {
			if strings.ContainsAny(m, " \u2028\u2029") || strings.Contains(m, "evil") || strings.HasPrefix(m, "<see") {
				t.Errorf("bad IRI term %s in %s", m, l)
			}
		}
	}
	both, err := Records(c, []core.Envelope{env, env})
	if err != nil || string(both) != text {
		t.Errorf("Records of one claim twice should be its Record: %v", err)
	}
}
