package core

import (
	"strings"
	"testing"
)

// canon(t, in) canonicalizes a JSON input string.
func canon(t *testing.T, in string) string {
	t.Helper()
	b, err := CanonJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonJSON(%q): %v", in, err)
	}
	return string(b)
}

// TestNormalizeContentHash: SPEC §5.1 - a content hash is "sha256:" + LOWERCASE hex. Normalization
// unifies the same digest written in non-canonical forms (uppercase, no prefix, padded) so it
// resolves to ONE identity; non-hashes (URIs, wrong length/alphabet) pass through with ok=false.
func TestNormalizeContentHash(t *testing.T) {
	lc := "sha256:" + strings.Repeat("ab", 32)
	for _, in := range []string{
		"sha256:" + strings.Repeat("AB", 32),          // uppercase hex
		"  sha256:" + strings.Repeat("Ab", 32) + "  ", // padded + mixed case
		strings.Repeat("aB", 32),                      // bare 64-hex, no prefix
		"SHA256:" + strings.Repeat("ab", 32),          // UPPERCASE prefix (kton blob accepts it; the index must too)
		"Sha256:" + strings.Repeat("AB", 32),          // mixed-case prefix + uppercase hex
	} {
		if n, ok := NormalizeContentHash(in); !ok || n != lc {
			t.Fatalf("NormalizeContentHash(%q) = %q ok=%v; want %q true", in, n, ok, lc)
		}
	}
	for _, bad := range []string{
		"sha256:deadbeef",                    // too short
		"urn:example:thing",                  // a URI, not a hash
		"md5:" + strings.Repeat("a", 32),     // wrong algorithm/length
		"sha256:" + strings.Repeat("zz", 32), // non-hex alphabet
	} {
		if n, ok := NormalizeContentHash(bad); ok || n != bad {
			t.Fatalf("NormalizeContentHash(%q) = %q ok=%v; want unchanged + false", bad, n, ok)
		}
	}
}

// TestJCSNumbers - RFC 8785 §3.2.2.3 (ECMAScript Number-to-String). The flagged gap: a naive
// serializer keeps whatever form it holds, so two implementations hash the same value differently.
func TestJCSNumbers(t *testing.T) {
	cases := map[string]string{
		`{"n":4.50}`:               `{"n":4.5}`,   // no trailing zero
		`{"n":1E30}`:               `{"n":1e+30}`, // lowercase e, explicit +
		`{"n":2e-3}`:               `{"n":0.002}`, // small exponent expanded
		`{"n":1e-27}`:              `{"n":1e-27}`, // very small -> exponent form
		`{"n":1.0}`:                `{"n":1}`,     // integer-valued -> "1"
		`{"n":1}`:                  `{"n":1}`,
		`{"n":1e0}`:                `{"n":1}`,
		`{"n":333333333.33333329}`: `{"n":333333333.3333333}`, // shortest IEEE 754 double
		`{"n":0}`:                  `{"n":0}`,
		`{"n":-0}`:                 `{"n":0}`, // -0 normalizes to 0
		`{"n":-1.5}`:               `{"n":-1.5}`,
		`{"n":100}`:                `{"n":100}`,
	}
	for in, want := range cases {
		if got := canon(t, in); got != want {
			t.Errorf("number canon %s -> %s, want %s", in, got, want)
		}
	}
}

// TestJCSStrings - RFC 8785 §3.2.2.2. Every backslash escape is written double-quoted ("\\u..."),
// i.e. a literal backslash-u in the JSON text - no raw control bytes appear in this source.
func TestJCSStrings(t *testing.T) {
	q, e := `{"s":"`, `"}`
	cases := []struct{ in, want string }{
		{q + "\\u000F" + e, q + "\\u000f" + e},                                     // hex lowercased
		{q + "\\u0001" + e, q + "\\u0001" + e},                                     // non-named control preserved
		{q + "\\u0008\\u0009\\u000a\\u000c\\u000d" + e, q + "\\b\\t\\n\\f\\r" + e}, // five named short escapes
		{`{"s":"€"}`, `{"s":"€"}`},                                                 // non-ASCII emitted literally
		{`{"s":"a/b"}`, `{"s":"a/b"}`},                                             // forward slash NOT escaped
		{q + "a\\/b" + e, `{"s":"a/b"}`},                                           // \/ input -> / output
	}
	for _, c := range cases {
		if got := canon(t, c.in); got != c.want {
			t.Errorf("string canon %s -> %s, want %s", c.in, got, c.want)
		}
	}
	// hex escapes are lowercase, never uppercase
	if got := canon(t, q+"\\u001F"+e); strings.Contains(got, "001F") {
		t.Errorf("hex escape must be lowercase, got %s", got)
	}
}

// TestJCSKeyOrder - object member names sorted by UTF-16 code units; array order preserved.
func TestJCSKeyOrder(t *testing.T) {
	if got := canon(t, `{"b":1,"a":2,"A":3}`); got != `{"A":3,"a":2,"b":1}` {
		t.Errorf("key order: got %s", got) // 'A'(0x41) < 'a'(0x61) < 'b'(0x62)
	}
	if got := canon(t, `{"x":[3,1,2]}`); got != `{"x":[3,1,2]}` {
		t.Errorf("array order must be preserved, got %s", got)
	}
}

// TestScenario1Equivalence - the interop-critical test: the same logical content in many cosmetic
// forms MUST canonicalize to one identical byte string and one identical hash.
func TestScenario1Equivalence(t *testing.T) {
	bs := "\\" // a single backslash, to compose the \/ escape without a raw \u in source
	variants := []string{
		`{"a":1,"n":1,"s":"/","u":"€"}`,
		`{"n":1,"a":1,"s":"/","u":"€"}`,              // reordered keys
		`{ "a" : 1 , "n" : 1 , "s" : "/", "u":"€" }`, // insignificant whitespace
		`{"a":1,"n":1.0,"s":"` + bs + `/","u":"€"}`,  // 1 vs 1.0, \/ vs /
		`{"a":1e0,"n":1,"s":"/","u":"€"}`,            // 1e0
	}
	want := canon(t, variants[0])
	h0 := HashBytes([]byte(want))
	for _, v := range variants[1:] {
		g := canon(t, v)
		if g != want {
			t.Fatalf("cosmetic variant diverged:\n got %s\nwant %s\n(%s)", g, want, v)
		}
		if HashBytes([]byte(g)) != h0 {
			t.Fatalf("same content, different hash - interop broken: %s", v)
		}
	}
}

// TestInvalidUnicodeDeterministic - I-JSON (RFC 7493) requires invalid Unicode to fail. The
// reference impl routes values through Go's json layer, which deterministically replaces invalid
// UTF-8 with U+FFFD rather than erroring; strict rejection is a documented 0.1 limitation (spec §5).
// What interop needs here is determinism, and it holds:
func TestInvalidUnicodeDeterministic(t *testing.T) {
	v := map[string]any{"s": string([]byte{0xff, 0xfe})}
	a, err := CanonValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := CanonValue(v); string(a) != string(b) {
		t.Fatal("canonicalization must be deterministic even for degenerate input")
	}
}

// TestCanonRejectsDuplicateKeys: RFC 8785 / I-JSON forbid duplicate object names. Go's decoder keeps
// last-wins, so an undetected dup means equal-id records differ in what a first-wins reader sees.
func TestCanonRejectsDuplicateKeys(t *testing.T) {
	for _, in := range []string{
		`{"x":"BENIGN","x":"EVIL"}`,
		`{"a":{"b":1,"b":2}}`,
		`{"arr":[{"k":1,"k":2}]}`,
	} {
		if _, err := CanonJSON([]byte(in)); err == nil {
			t.Errorf("CanonJSON(%s) must reject a duplicate key", in)
		}
	}
	// a repeated key in DIFFERENT objects is fine
	if _, err := CanonJSON([]byte(`{"a":{"k":1},"b":{"k":2}}`)); err != nil {
		t.Errorf("distinct objects sharing a key name must be allowed: %v", err)
	}
}

// TestCanonRejectsImpreciseIntegers: an integer past 2^53 loses precision as a double, so two claims
// differing by 1 would share an id (RFC 8785 App D: carry such values as strings).
func TestCanonRejectsImpreciseIntegers(t *testing.T) {
	for _, bad := range []string{`{"n":9007199254740993}`, `{"n":123456789012345678901234}`} {
		if _, err := CanonJSON([]byte(bad)); err == nil {
			t.Errorf("CanonJSON(%s) must reject an imprecise integer", bad)
		}
	}
	for _, ok := range []string{`{"n":9007199254740992}`, `{"n":-9007199254740991}`, `{"n":0}`, `{"n":42}`} {
		if _, err := CanonJSON([]byte(ok)); err != nil {
			t.Errorf("CanonJSON(%s) must accept an exactly-representable integer: %v", ok, err)
		}
	}
}
