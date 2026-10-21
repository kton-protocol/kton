package rdf

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// A foton's own quads are the same bytes whoever signed it and however many signatures its envelope
// carries; its attribution comes back once per verifying key, each in its own graph (#232).
func TestRecordIsTheRecordAloneAndAttributionIsPerKey(t *testing.T) {
	pubA, privA := key(t)
	pubB, privB := key(t)
	pubC, _ := key(t)
	single, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	both, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := single.Add(coSigned(t, []ed25519.PrivateKey{privA}, []string{core.KeyIDHex(pubA)}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := both.Add(coSigned(t, []ed25519.PrivateKey{privA, privB}, []string{core.KeyIDHex(pubA), core.KeyIDHex(pubB)})); err != nil {
		t.Skipf("the registry refuses this envelope: %v", err)
	}
	a, err := Record(single, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Record(both, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("own quads differ with the signature set:\n%s\nvs\n%s", a, b)
	}
	for _, bad := range []string{"wasAttributedTo", "signerVerified", "claimedSigner", "/agent/"} {
		if strings.Contains(string(a), bad) {
			t.Errorf("own quads carry %s:\n%s", bad, a)
		}
	}
	g := "<" + RecordGraph(id) + "> ."
	for _, l := range strings.Split(strings.TrimSpace(string(a)), "\n") {
		if !strings.HasSuffix(l, g) {
			t.Errorf("own quad outside the record graph: %s", l)
		}
	}

	if batch, err := Records(both, []string{id, id}); err != nil || string(batch) != string(b) {
		t.Errorf("Records of one foton twice should be its Record: %v", err)
	}

	att, err := Attribution(both, id, []ed25519.PublicKey{pubA, pubB, pubA, pubC})
	if err != nil {
		t.Fatal(err)
	}
	if len(att) != 2 || att[core.KeyIDHex(pubA)] == nil || att[core.KeyIDHex(pubB)] == nil {
		t.Fatalf("attribution for %d keys, want A and B", len(att))
	}
	for kid, q := range att {
		if !strings.Contains(string(q), "<"+AttributionGraph(id, kid)+"> .") || !strings.Contains(string(q), "/agent/"+kid+">") {
			t.Errorf("attribution of %s:\n%s", kid, q)
		}
	}
}

// A path is signed record data: in N-Quads it stays one literal, and the line count is the line count.
func TestNQuadsLiteralCannotEndTheLine(t *testing.T) {
	got := nqLiteral("a\" <x> <y> <z> <g> .\nb\x01\\")
	if strings.Count(got, "\n") != 0 || !strings.HasPrefix(got, `"a\"`) || !strings.Contains(got, `\u0001`) || !strings.HasSuffix(got, `\\"`) {
		t.Errorf("literal %s", got)
	}
}
