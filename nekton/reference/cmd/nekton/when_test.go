package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A scope id IS the seed's claim id, and the claim id covers `when`. With the timestamp taken from
// the wall clock, seeding the same scope with the same key from the same inputs opened a DIFFERENT
// scope on every rebuild (#42): a 2243-claim corpus produced three different root ids in three
// runs, and every child scope and claim moved with it. --when makes the identity a function of the
// inputs again.
func TestSeedWithExplicitWhenIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k.key")
	if err := keygen([]string{filepath.Join(dir, "k")}); err != nil {
		t.Fatal(err)
	}

	seedOnce := func(reg string) string {
		t.Helper()
		out := filepath.Join(dir, reg+".dsse.json")
		if err := seed([]string{"demo", "--sign", key, "--when", "2026-07-16T00:00:00Z", "-o", out}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	first := seedOnce("a")
	time.Sleep(1100 * time.Millisecond) // cross an RFC 3339 second boundary: without --when these differ
	second := seedOnce("b")

	if first != second {
		t.Error("two seeds with the same --when produced different envelopes; the scope id is still time-dependent")
	}

	// The control: the same seed WITHOUT --when must land in a different second and so a different
	// scope. If this ever stops differing, the test above has stopped proving anything.
	outC := filepath.Join(dir, "c.dsse.json")
	if err := seed([]string{"demo", "--sign", key, "-o", outC}); err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(outC)
	if string(c) == first {
		t.Error("a wall-clock seed matched the pinned one; the control is not exercising anything")
	}
}

// A bad --when must be refused BEFORE signing. A timestamp caught only at ingest has already been
// signed, and the signature stands over the garbage.
func TestBadWhenIsRefusedBeforeSigning(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k")}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bad.dsse.json")
	err := seed([]string{"demo", "--sign", filepath.Join(dir, "k.key"), "--when", "yesterday", "-o", out})
	if err == nil {
		t.Fatal("a non-RFC3339 --when was accepted")
	}
	if !strings.Contains(err.Error(), "RFC 3339") {
		t.Errorf("error does not say what is wrong with it: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a signed envelope was written despite the bad timestamp")
	}
}

// The other half of a reproducible record id. --when pins the timestamp; the public key sits inside
// every signed payload too, so a random key per run moves every id regardless (#44). A seeded key
// makes the identity a function of its input, and pubkey recovers the .pub that verify,
// --trust-keys and the viewer key dirs read.
func TestSeededKeygenIsDeterministicAndPubkeyRecoversIt(t *testing.T) {
	dir := t.TempDir()
	const seed = "1f8caf6e0000000000000000000000000000000000000000000000000000beef"

	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}

	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, n := range []string{a, b} {
		if err := keygen([]string{n, "--seed", seed}); err != nil {
			t.Fatalf("keygen --seed: %v", err)
		}
	}
	if read(a+".pub") != read(b+".pub") {
		t.Error("the same --seed produced different public keys")
	}
	if read(a+".key") != seed {
		t.Errorf("the .key is not the seed it was given: %s", read(a+".key"))
	}

	// The control: without --seed the keys must differ, or the assertion above proves nothing.
	c := filepath.Join(dir, "c")
	if err := keygen([]string{c}); err != nil {
		t.Fatal(err)
	}
	if read(c+".pub") == read(a+".pub") {
		t.Error("a random keygen matched the seeded one")
	}

	// pubkey recovers the same hex from the private half alone - including a hand-written seed that
	// never went through keygen, which is the case that motivated this.
	hand := filepath.Join(dir, "hand.key")
	if err := os.WriteFile(hand, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{a + ".key", hand, seed} {
		out := captureStdout(t, func() {
			if err := pubkey(in); err != nil {
				t.Fatalf("pubkey %q: %v", in, err)
			}
		})
		if strings.TrimSpace(out) != read(a+".pub") {
			t.Errorf("pubkey %q = %q, want %q", in, strings.TrimSpace(out), read(a+".pub"))
		}
	}

	if err := pubkey("not-a-key"); err == nil {
		t.Error("pubkey accepted a non-key")
	}
	if err := keygen([]string{filepath.Join(dir, "z"), "--seed", "abcd"}); err == nil {
		t.Error("keygen accepted a short seed")
	}
}
