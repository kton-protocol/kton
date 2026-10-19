package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A seed's scope NAME is signed record data, and `export --nanopub` used to write it straight into
// <urn:nekton:scope:...>. A name carrying `>` and a newline closed the IRI and the assertion graph,
// and opened a graph of its own - here a provenance graph attributing the claim to an agent nobody
// verified. The export of a valid, signed seed must stay exactly the four nanopub graphs.
func TestSeedScopeNameCannotOpenGraphsInTheExport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NEKTON_DIR", filepath.Join(dir, "reg"))
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("5e", 32)}); err != nil {
		t.Fatal(err)
	}
	name := "x> a <https://kton.dev/v/nk/Scope> .\n}\n<https://kton.dev/np/FORGED#provenance> {\n" +
		"  <https://kton.dev/np/FORGED#assertion> <http://www.w3.org/ns/prov#wasAttributedTo> <https://kton.dev/agent/c0ffee> .\n" +
		"}\nsub:assertion {\n  <urn:nekton:scope:y"
	seedOut := filepath.Join(dir, "seed.dsse.json")
	if err := seed([]string{name, "--sign", filepath.Join(dir, "k.key"),
		"--when", "2026-07-16T00:00:00Z", "-o", seedOut}); err != nil {
		t.Skipf("the seed name is refused at authoring, so nothing reaches the export: %v", err)
	}
	trig := filepath.Join(dir, "seed.trig")
	if err := exportNanopub([]string{seedOut, "-o", trig}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(trig)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	// The name still appears, inert, inside the quoted rdfs:label; what must not exist is a line
	// that STARTS a term with it.
	if regexp.MustCompile(`(?m)^\s*<https://kton\.dev/np/FORGED`).MatchString(out) {
		t.Errorf("the scope name opened a graph of its own in the export:\n%s", out)
	}
	graphs := regexp.MustCompile(`(?m)^\S[^\n]*\{$`).FindAllString(out, -1)
	if len(graphs) != 4 {
		t.Errorf("export has %d graphs, want the 4 of a nanopublication (Head, assertion, provenance, pubinfo): %q\n%s",
			len(graphs), graphs, out)
	}
	if !strings.Contains(out, "<urn:nekton:scope:x%3E%20a%20%3Chttps://kton.dev/v/nk/Scope%3E%20.%0A%7D") {
		t.Errorf("the scope IRI is not the escaped name:\n%s", out)
	}
}

// A raw CR is not allowed in a Turtle string literal, and one such value made the whole document
// unparseable. Every control character is escaped; the literal's value does not change.
func TestQuoteEscapesEveryControlCharacter(t *testing.T) {
	got := quote("a\rb\nc\td\"e\\f\x01g\x7fhé")
	want := `"a\rb\nc\td\"e\\f\u0001g\u007Fhé"`
	if got != want {
		t.Fatalf("quote = %s, want %s", got, want)
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("quote left a raw control character %U in %q", r, got)
		}
	}
}

// PN_LOCAL may not start with '-' or '.', nor end with '.'. Such a local part falls back to an
// escaped full IRI instead of a prefixed name a Turtle parser refuses.
func TestSafePNLocalRefusesWhatTurtleRefuses(t *testing.T) {
	for _, bad := range []string{"", "-a", ".a", "a.", "a b", "a/b"} {
		if safePNLocal(bad) {
			t.Errorf("safePNLocal(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"a", "a-b", "a.b", "_a", "0a", "reviewed"} {
		if !safePNLocal(ok) {
			t.Errorf("safePNLocal(%q) = false, want true", ok)
		}
	}
}
