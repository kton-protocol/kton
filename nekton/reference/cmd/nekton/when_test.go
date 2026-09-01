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
	if err := keygen(filepath.Join(dir, "k")); err != nil {
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
	if err := keygen(filepath.Join(dir, "k")); err != nil {
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
