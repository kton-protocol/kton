package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// L0 means "the same output bytes", and `ref == cand` is how that is decided - so both arguments
// have to BE content hashes before they are compared. If normalization can fail silently, two equal
// malformed strings report a match over strings that name no bytes, and a caller passing through a
// broken variable gets a successful reproduction claim instead of an error.
func TestReproducesRefusesArgumentsThatAreNotHashes(t *testing.T) {
	h := "sha256:" + strings.Repeat("a", 64)

	t.Run("equal junk is not a reproduction", func(t *testing.T) {
		for _, bad := range []string{
			"not-a-hash",
			"sha256:" + strings.Repeat("a", 63), // one hex digit short
			"sha256:" + strings.Repeat("z", 64), // right length, not hex
			"md5:" + strings.Repeat("a", 32),    // an algorithm this version does not emit
			"",
		} {
			if err := run("reproduces", []string{bad, bad, "--json"}); err == nil {
				t.Errorf("reproduces %q %q reported a match; equality of two malformed strings is not one", bad, bad)
			}
		}
	})

	// The refusal must not cost the legitimate comparison: equivalent SPELLINGS of one hash still
	// compare equal, which is the whole point of normalizing before comparing.
	t.Run("equivalent spellings still compare equal", func(t *testing.T) {
		for _, pair := range [][2]string{
			{h, h},
			{strings.Repeat("a", 64), h},             // bare hex vs prefixed
			{h, "SHA256:" + strings.Repeat("A", 64)}, // case
			{h, "  " + h + "\n"},                     // surrounding whitespace
		} {
			raw := captureStdout(t, func() {
				if err := run("reproduces", []string{pair[0], pair[1], "--json"}); err != nil {
					t.Fatalf("reproduces %q %q: %v", pair[0], pair[1], err)
				}
			})
			var got struct {
				Level   string `json:"level"`
				Matched bool   `json:"matched"`
			}
			if err := json.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("not valid JSON: %v\n%s", err, raw)
			}
			if got.Level != "L0" || !got.Matched {
				t.Errorf("reproduces %q %q = %+v; want an L0 match", pair[0], pair[1], got)
			}
		}
	})
}
