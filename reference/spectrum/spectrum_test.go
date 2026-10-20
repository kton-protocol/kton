package spectrum

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

func h(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// record adds a signed foton in -> out under protocol ref to r.
func record(t *testing.T, r *registry.Registry, priv ed25519.PrivateKey, in, out, ref string) {
	t.Helper()
	digest := func(x string) map[string]any { return map[string]any{"sha256": strings.TrimPrefix(x, "sha256:")} }
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out", "digest": digest(out)}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in", "digest": digest(in)}},
			"protocol": map[string]any{"kind": "run", "ref": ref},
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(sig)})
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
}

// fixture: references a, b and c are recorded outputs; a candidate run produced a (identical), b2 (a
// different raw output of b that the normalizer maps to the same canonical form) and x (wrong).
func fixture(t *testing.T) (*registry.Registry, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gold, cand, norm := h("gold-tool"), h("candidate-tool"), h("normalizer")
	for _, o := range []string{"a", "b", "c"} {
		record(t, r, priv, h("data-"+o), h(o), gold)
	}
	for _, o := range []string{"a", "b2", "x"} {
		record(t, r, priv, h("data-"+o), h(o), cand)
	}
	record(t, r, priv, h("b"), h("b-canonical"), norm)
	record(t, r, priv, h("b2"), h("b-canonical"), norm)
	return r, norm
}

func spec(norm string, members ...string) Spectrum {
	s := Spectrum{Spectrum: "tool", Normalizer: norm}
	for _, m := range members {
		s.Members = append(s.Members, Member{Name: m, Output: h(m)})
	}
	return s
}

func TestCheckReportsEachMember(t *testing.T) {
	r, norm := fixture(t)
	res, err := Check(r, spec(norm, "a", "b", "c"), map[string]string{"a": h("a"), "b": h("b2"), "c": h("x")})
	if err != nil {
		t.Fatal(err)
	}
	want := []Status{Identical, Via, NotFulfilled}
	for i, m := range res.Members {
		if m.Status != want[i] {
			t.Errorf("member %s: got %s, want %s", m.Name, m.Status, want[i])
		}
	}
	if res.Fulfilled != 2 || res.Outcome() != OutcomeFailed {
		t.Errorf("got %d fulfilled, outcome %s; want 2, failed", res.Fulfilled, res.Outcome())
	}
}

// Spec-test Scenario 7 (the half-passing candidate): reproducing some members is not fulfilment.
func TestPartialFulfilmentIsNotFulfilment(t *testing.T) {
	r, _ := fixture(t)
	res, err := Check(r, spec("", "a", "c"), map[string]string{"a": h("a"), "c": h("x")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fulfilled != 1 || res.Outcome() != OutcomeFailed {
		t.Errorf("got %d fulfilled, outcome %s; want 1, failed", res.Fulfilled, res.Outcome())
	}
}

func TestNoCandidateIsIncompleteNotFailed(t *testing.T) {
	r, _ := fixture(t)
	res, err := Check(r, spec("", "a", "b"), map[string]string{"a": h("a")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Members[1].Status != NoCandidate || res.Missing != 1 || res.Outcome() != OutcomeIncomplete {
		t.Errorf("got %+v, outcome %s; want b no-candidate, incomplete", res, res.Outcome())
	}
	if res, _ := Check(r, spec("", "a", "b"), map[string]string{"a": h("a"), "b": h("b")}); res.Outcome() != OutcomeFulfilled {
		t.Errorf("every member fulfilled: got outcome %s", res.Outcome())
	}
}

// Hashes that back no recorded computation must not score as identical: equal strings are not a
// reproduction unless both are outputs of fotons in the registry.
func TestInventedHashesFulfilNothing(t *testing.T) {
	r, _ := fixture(t)
	ghost := h("never-computed")
	res, err := Check(r, Spectrum{Spectrum: "tool", Members: []Member{{Name: "g", Output: ghost}}}, map[string]string{"g": ghost})
	if err != nil {
		t.Fatal(err)
	}
	if res.Members[0].Status != ReferenceNotRecorded || res.Outcome() != OutcomeFailed {
		t.Errorf("fabricated reference: got %s, outcome %s", res.Members[0].Status, res.Outcome())
	}
	res, err = Check(r, spec("", "a"), map[string]string{"a": ghost})
	if err != nil {
		t.Fatal(err)
	}
	if res.Members[0].Status != CandidateNotRecorded {
		t.Errorf("fabricated candidate: got %s", res.Members[0].Status)
	}
}

func TestCheckRefuses(t *testing.T) {
	r, _ := fixture(t)
	for name, tc := range map[string]struct {
		s    Spectrum
		cand map[string]string
		want string
	}{
		"no members":       {Spectrum{Spectrum: "tool"}, nil, "defines no members"},
		"unknown member":   {spec("", "a"), map[string]string{"a": h("a"), "typo": h("a")}, "names no member"},
		"not a hash":       {spec("", "a"), map[string]string{"a": "sha256:abc"}, "content hash"},
		"uppercase digest": {spec("", "a"), map[string]string{"a": strings.ToUpper(h("a"))}, "content hash"},
	} {
		if _, err := Check(r, tc.s, tc.cand); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}
