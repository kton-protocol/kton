package core

import "testing"

// A subject without a valid sha256 digest must yield an EMPTY Hash, not a malformed "sha256:"
// (an in-toto subject with a different digest algorithm, or none, is not content-addressed here).
func TestSubjectToRefMissingDigest(t *testing.T) {
	if got := subjectToRef(Subject{Name: "x", Digest: map[string]string{}}); got.Hash != "" {
		t.Errorf("digest-less subject: Hash = %q, want empty", got.Hash)
	}
	if got := subjectToRef(Subject{Name: "x", Digest: map[string]string{"sha512": "abc"}}); got.Hash != "" {
		t.Errorf("non-sha256 subject: Hash = %q, want empty", got.Hash)
	}
	const h = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got := subjectToRef(Subject{Name: "x", Digest: map[string]string{"sha256": h}}); got.Hash != "sha256:"+h {
		t.Errorf("valid subject: Hash = %q, want sha256:%s", got.Hash, h)
	}
}
