package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"
)

// canonicalize must be deterministic, sorted, and blank the nanopub's own base (so the Trusty URI and
// the RSA signature are independent of the not-yet-minted self URI).
func TestCanonicalizeDeterministicAndSelfBaseBlanked(t *testing.T) {
	qs := []npQuad{
		{s: npTempBase, p: "http://x/p", g: npTempBase + "#g", o: iriT(npTempBase + "#o")},
		{s: npTempBase + "#o", p: "http://x/lit", g: npTempBase + "#g", o: litT("hi \"q\"\n", "")},
	}
	a, b := canonicalize(qs), canonicalize(qs)
	if string(a) != string(b) {
		t.Fatal("canonicalize is not deterministic")
	}
	if strings.Contains(string(a), npTempBase) {
		t.Fatalf("self-base leaked into the canonical form (would make the name self-dependent): %s", a)
	}
	if !strings.Contains(string(a), npSelfMark) {
		t.Fatal("self-base placeholder missing")
	}
	lines := strings.Split(strings.TrimRight(string(a), "\n"), "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			t.Fatalf("canonical lines are not sorted: %q !< %q", lines[i-1], lines[i])
		}
	}
}

// The RSA signature is a genuine PKCS#1 v1.5 / SHA-256 signature over the canonical bytes: it verifies,
// and a tampered digest does not. The Trusty URI carries the RA artifact code.
func TestRSASignVerifyOverCanonical(t *testing.T) {
	canon := canonicalize([]npQuad{{s: npTempBase, p: "http://x/p", g: npTempBase + "#g", o: litT("v", "")}})
	d := sha256.Sum256(canon)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		t.Fatalf("fresh signature did not verify: %v", err)
	}
	tampered := sha256.Sum256(append(append([]byte{}, canon...), 'x'))
	if rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, tampered[:], sig) == nil {
		t.Fatal("a tampered digest verified against the signature")
	}
	if !strings.HasPrefix(trustyURI(canon), "RA") {
		t.Fatalf("Trusty URI must carry the RA artifact code, got %s", trustyURI(canon))
	}
}

// TestIriEscBlocksInjection: a crafted IRI containing Turtle-illegal chars is percent-escaped so it
// stays one inert term - it cannot close the <...> and inject a triple into the signed graph.
func TestIriEscBlocksInjection(t *testing.T) {
	bad := "http://x/ok> . sub:o <p> <https://kton.dev/agent/CEO-BOARD"
	got := iriEsc(bad)
	if strings.ContainsAny(got, "<> ") {
		t.Fatalf("iriEsc left an injection char in %q", got)
	}
	if got == bad {
		t.Fatal("iriEsc did not escape the payload")
	}
	// a legitimate IRI is unchanged (no forbidden chars)
	ok := "https://kton.dev/v/gxp/reviewed"
	if iriEsc(ok) != ok {
		t.Fatalf("iriEsc must not alter a legitimate IRI, got %q", iriEsc(ok))
	}
}
