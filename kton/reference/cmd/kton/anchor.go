package main

// anchor.go adds the OPTIONAL Sigstore trust-anchoring surface: submit a signed statement to the
// Rekor transparency log and verify its inclusion. This is not part of the kernel - plankton
// records fotons and never needs the network - it is a cockpit-invoked capability that gives a
// signed record a tamper-evident, timestamped public witness. The verified Rekor coordinates
// (logIndex + inclusion proof + SET) are meant to be stored as a sidecar on the claim/foton.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/kton/sigstore"
)

func rekorURL() string { return os.Getenv("KTON_REKOR_URL") } // "" → public Rekor

// trustedRekorPub returns the Rekor public key to verify the SET against. It must be a PINNED key -
// NEVER the key the log endpoint serves for ITSELF, or a fabricated entry from an attacker-controlled
// KTON_REKOR_URL would self-verify (its own SET, signed by its own key, checked against that same
// key). So: a pinned key from KTON_REKOR_PUBKEY (a PEM file path or inline PEM) is always used; a
// CUSTOM endpoint with no pinned key is REFUSED; only the well-known PUBLIC Rekor may fall back to the
// fetched key, and then only with an explicit "unpinned - trust-on-first-use" caveat.
func trustedRekorPub(url string) (*ecdsa.PublicKey, error) {
	if pin := os.Getenv("KTON_REKOR_PUBKEY"); pin != "" {
		txt := pin
		if b, err := os.ReadFile(pin); err == nil {
			txt = string(b)
		}
		blk, _ := pem.Decode([]byte(txt))
		if blk == nil {
			return nil, fmt.Errorf("KTON_REKOR_PUBKEY: not a PEM public key")
		}
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("KTON_REKOR_PUBKEY: not an ECDSA key")
		}
		return ec, nil
	}
	if url != "" {
		return nil, fmt.Errorf("a custom Rekor endpoint (KTON_REKOR_URL=%s) MUST be paired with a pinned public key in KTON_REKOR_PUBKEY; refusing to trust the key the endpoint serves for itself (a fabricated entry would otherwise self-verify)", url)
	}
	// Default PUBLIC Rekor with no pinned key: trust-on-first-use only. Fetch, but say so loudly.
	fmt.Fprintln(os.Stderr, "warning: verifying against the key the PUBLIC Rekor endpoint serves for itself (UNPINNED, trust-on-first-use); set KTON_REKOR_PUBKEY to a pinned key for a real trust root.")
	return sigstore.PublicKey(url)
}

// anchor submits <envelope.dsse.json> (signed by the key whose public half is <pubkey.hex>) to
// Rekor, verifies the returned inclusion proof + SET against Rekor's public key, and prints the
// entry as JSON (the sidecar to store).
func anchor(envPath, pubHexPath string) error {
	env, err := readEnvelope(envPath)
	if err != nil {
		return err
	}
	txt := pubHexPath
	if b, err := os.ReadFile(pubHexPath); err == nil {
		txt = string(b) // a .pub file path...
	} // ...or the hex string itself
	pub, err := core.ParsePublicKeyHex(strings.TrimSpace(txt))
	if err != nil {
		return err
	}
	verifierPEM, err := sigstore.Ed25519VerifierPEM(pub)
	if err != nil {
		return err
	}
	entry, err := sigstore.Anchor(rekorURL(), env, verifierPEM)
	if err != nil {
		return err
	}
	rpub, err := trustedRekorPub(rekorURL())
	if err != nil {
		return err
	}
	if err := entry.VerifySET(rpub); err != nil {
		return fmt.Errorf("Rekor SET did not verify: %w", err)
	}
	if err := entry.VerifyInclusion(); err != nil {
		return fmt.Errorf("Rekor inclusion proof did not verify: %w", err)
	}
	// The SET + inclusion proof only say "this is a genuine Rekor entry" - NOT "this is YOUR record". A
	// hostile endpoint can replay a real, unrelated entry; bind the entry to the submitted envelope +
	// verifier so a replay is rejected (a record honest Rekor would 400 must not print "anchored").
	if err := entry.VerifyBinds(env, verifierPEM); err != nil {
		return fmt.Errorf("Rekor entry is not bound to this record: %w", err)
	}
	fmt.Printf("anchored in Rekor: logIndex=%d  uuid=%s\n", entry.LogIndex, entry.UUID)
	fmt.Println("  inclusion proof + SET verified against Rekor's public key (independent witness)")
	out, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
