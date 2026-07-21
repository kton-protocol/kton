package main

import (
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// TestAuthoringNormalizesSubjectHashCase: a claim authored with an uppercase/mixed-case subject
// digest must produce the SAME canonical subject bytes (hence the same claim id) as the canonical
// lowercase form, and must emit lowercase on the wire (SPEC §5.1). This is what makes the §12
// conflict-free union dedup case-variant claims rather than storing duplicates.
func TestAuthoringNormalizesSubjectHashCase(t *testing.T) {
	up := "sha256:" + strings.Repeat("AB", 32)
	lo := "sha256:" + strings.Repeat("ab", 32)
	bu, err := core.CanonValue(subjectsOf([]subjSpec{{Hash: up}}))
	if err != nil {
		t.Fatal(err)
	}
	bl, err := core.CanonValue(subjectsOf([]subjSpec{{Hash: lo}}))
	if err != nil {
		t.Fatal(err)
	}
	if string(bu) != string(bl) {
		t.Fatalf("case-variant subject must canonicalize identically:\n up=%s\n lo=%s", bu, bl)
	}
	if strings.Contains(string(bu), "AB") {
		t.Fatalf("authored subject must be lowercase (SPEC 5.1), got %s", bu)
	}
}
