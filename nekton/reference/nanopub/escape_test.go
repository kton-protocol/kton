package nanopub

import "testing"

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
