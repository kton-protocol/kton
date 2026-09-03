package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A located-at claim is a SUGGESTION from whoever signed it, and ingest stores signed claims
// without verifying them (SPEC §8: the wire carries a keyid, not a key). So "it is in the registry"
// said nothing about who put it there - and fetch opened the URI anyway.
//
// Dereferencing is a request made from this host, and for file:// a read of this disk. The hash
// check that follows proves what the bytes ARE; it cannot undo the request, and for a file whose
// hash is known it does not even reject the result (AUD-03).
func TestDerefRefusesWhatASignatureCannotVouchFor(t *testing.T) {
	// file:// names a path on THIS machine. Even a verified signer's signature is about CONTENT and
	// says nothing about the local filesystem, so it needs a second, explicit yes.
	if _, err := deref("file:///etc/hostname", false); err == nil {
		t.Error("a file:// locator was dereferenced without --allow-local")
	} else if !strings.Contains(err.Error(), "--allow-local") {
		t.Errorf("the refusal does not say how to proceed deliberately: %v", err)
	}

	// Loopback and the link-local range (where cloud metadata services live) are refused by default.
	srv := httptest.NewServer(nil)
	defer srv.Close()
	if _, err := deref(srv.URL, false); err == nil {
		t.Error("a loopback locator was dereferenced")
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1"} {
		if err := checkDestination(host, false); err == nil {
			t.Errorf("checkDestination(%q) allowed it", host)
		}
		// --allow-local is an operator decision, and it must actually work.
		if err := checkDestination(host, true); err != nil {
			t.Errorf("checkDestination(%q, allowLocal) refused: %v", host, err)
		}
	}

	// An unknown scheme is refused rather than guessed at.
	if _, err := deref("gopher://example.org/x", true); err == nil {
		t.Error("an unknown scheme was dereferenced")
	}
}
