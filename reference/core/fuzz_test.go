package core

import (
	"strings"
	"testing"
)

// The canonicalizer is the first thing every untrusted byte meets: an envelope's payload, an
// authoring spec, a descriptor. Everything downstream - identity, signatures, the action key - rests
// on it not misbehaving on input nobody anticipated.
//
// Two properties, both of which the code has broken before:
//
//   - it must not PANIC. A crash on a malformed record is a denial of service on a store: one
//     planted file is read by every process that opens it.
//   - whatever it ACCEPTS, it must accept again unchanged. canon(canon(x)) == canon(x) failed for a
//     whole class of numbers and no example-based test would have caught it, because they
//     all used values someone had already thought of.
//
// Search with: go test ./core/ -fuzz FuzzCanonJSON
// CI runs the seed corpus only, which is still worth having - the seeds are the shapes that bit us.
func FuzzCanonJSON(f *testing.F) {
	for _, seed := range []string{
		"{}", "[]", "null", "0", "-0", "1e20", "9007199254740993", "9007199254740993.0",
		"1e-7", "12345678901234567890.5", `{"a":1,"a":2}`, `{"x":1} {"y":2}`,
		`{"s":"\ud800"}`, `{"n":[1,{"m":true}]}`, `{"z":null,"a":" "}`,
		`{"deep":{"deep":{"deep":[1e308]}}}`, strings.Repeat("[", 64),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := CanonJSON(in)
		if err != nil {
			return // refusing is always allowed; crashing is not
		}
		again, err := CanonJSON(out)
		if err != nil {
			t.Fatalf("canonical output refused on a second pass\n in:  %q\n out: %q\n err: %v", in, out, err)
		}
		if string(again) != string(out) {
			t.Fatalf("not idempotent\n in:    %q\n once:  %q\n twice: %q", in, out, again)
		}
	})
}

// A content hash arrives from a peer, a filename, a CLI argument. Normalizing it must be total, and
// must agree with itself: a hash that normalizes must normalize to a FIXED POINT, or the same bytes
// index under two keys and a record becomes invisible to a consumer resolving the other spelling.
func FuzzNormalizeContentHash(f *testing.F) {
	for _, seed := range []string{
		"sha256:" + strings.Repeat("ab", 32), strings.Repeat("AB", 32), "  sha256:x  ",
		"sha256:", "sha512:" + strings.Repeat("ab", 64), "", "sha256:zz",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		norm, ok := NormalizeContentHash(in)
		if !ok {
			return
		}
		again, ok2 := NormalizeContentHash(norm)
		if !ok2 || again != norm {
			t.Fatalf("normalization is not a fixed point: %q -> %q -> %q (ok=%v)", in, norm, again, ok2)
		}
	})
}
