package blobstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// path used to check only that the string was 64 characters long, and 64 characters can contain
// separators and "..", which filepath.Join then normalises away. os.ReadFile ran on the result
// BEFORE the hash comparison that would have rejected it, and /blob?hash= feeds a query parameter
// straight in, unauthenticated (AUD-04).
//
// The mismatch still stopped the bytes being returned as a blob, so this was never byte disclosure.
// It was an existence-and-timing oracle and a way to pull an arbitrary large file into memory - and
// the read is the part a later check cannot undo.
func TestPathRefusesAnythingThatIsNotAContentHash(t *testing.T) {
	root := t.TempDir()
	// A sentinel OUTSIDE the store, so a successful escape would be observable.
	outside := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(outside, []byte("not yours"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}

	sixtyFour := func(x string) string {
		for len(x) < 64 {
			x += "a"
		}
		return x[:64]
	}
	for _, bad := range []string{
		sixtyFour("../../../../etc/passwd"),
		sixtyFour("..%2f..%2fsecret"),
		sixtyFour("../secret.txt"),
		strings.Repeat("z", 64), // right length, not hex
		"sha256:" + strings.Repeat("g", 64),
		"", "sha256:", strings.Repeat("a", 63), strings.Repeat("a", 65),
	} {
		if p, err := s.path(bad); err == nil {
			t.Errorf("path(%q) returned %q; want a refusal BEFORE any filesystem access", bad, p)
		}
		// Has() and Get() must refuse for the same reason, since they are the reachable surface.
		if s.Has(bad) {
			t.Errorf("Has(%q) = true", bad)
		}
		if _, err := s.Get(bad); err == nil {
			t.Errorf("Get(%q) succeeded", bad)
		}
	}

	// The real thing still round-trips, in every accepted spelling.
	h, err := s.Put([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{h, strings.ToUpper(h), strings.TrimPrefix(h, "sha256:")} {
		if _, err := s.Get(form); err != nil {
			t.Errorf("Get(%q): %v - SPEC §5.1 accepts a bare or uppercase digest", form, err)
		}
	}
}
