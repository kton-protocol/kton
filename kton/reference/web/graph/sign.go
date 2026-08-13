package main

// sign.go is the browser SIGN side, the counterpart to graph.go's verify side.
//
// The kernel does the parts that must match it exactly - canonicalization, the claim id, and the
// DSSE Pre-Authentication Encoding - and hands the raw bytes-to-sign back to JavaScript. The
// actual Ed25519 signature is made by WebCrypto, over a key created with `extractable: false`.
// That split is the point: the private key is unexportable, never crosses into Go's memory, and
// cannot be read back out by any script on the page. Go only ever sees a public key and a
// finished signature.
//
// Because the payload is assembled by claim.StatementPayload - the same function `nekton claim`
// uses - a claim signed in a browser is byte-identical to the same claim signed by the CLI, and
// therefore carries the same claim id and deduplicates correctly in a federated union.
//
// No build tag: this file compiles natively too, so the `go run ./web/graph` harness and normal
// `go test` exercise the exact code the browser runs.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// KeyIRI is the content-addressed IRI of a public key: the subject a `sec:controller` identity
// binding is made about (kton-examples example 07). It is the FULL sha256 of the raw public key
// bytes, not the 16-hex display keyid, so the IRI cannot collide.
func KeyIRI(pubHex string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil {
		return "", fmt.Errorf("public key is not hex: %w", err)
	}
	if _, err := core.ParsePublicKeyHex(strings.TrimSpace(pubHex)); err != nil {
		return "", err
	}
	s := sha256.Sum256(raw)
	return "https://kton.dev/o/" + hex.EncodeToString(s[:]), nil
}

// BuildClaim turns claim-spec JSON into the canonical payload and the exact bytes to sign.
// Both are returned base64-encoded because that survives the Go/JS boundary unambiguously; the
// lens decodes `toSign` before handing it to crypto.subtle.sign.
func BuildClaim(specJSON string) (map[string]any, error) {
	spec, err := claim.ParseSpec([]byte(specJSON))
	if err != nil {
		return nil, fmt.Errorf("claim spec is not valid JSON: %w", err)
	}
	payload, toSign, err := claim.SigningInput(spec)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"payloadType": core.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"toSign":      base64.StdEncoding.EncodeToString(toSign),
	}, nil
}

// SealClaim reassembles a WebCrypto signature into a DSSE envelope and returns the registry
// record JSON ({claimId, envelope}) ready to POST to the bridge.
//
// claim.Seal re-verifies the signature against the public key before returning, so a mismatched
// key/signature pair fails HERE - in the browser, with a clear message - rather than being posted
// and silently rejected by the registry later.
func SealClaim(payloadB64, sigB64, pubHex string) (map[string]any, error) {
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("payload is not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64: %w", err)
	}
	pub, err := core.ParsePublicKeyHex(strings.TrimSpace(pubHex))
	if err != nil {
		return nil, err
	}
	env, id, err := claim.Seal(payload, sig, pub)
	if err != nil {
		return nil, err
	}
	rec, err := json.Marshal(map[string]any{"claimId": id, "envelope": env})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"claimId": id,
		"keyid":   core.KeyIDHex(pub),
		"keyIRI":  mustKeyIRI(pubHex),
		"record":  string(rec),
	}, nil
}

// mustKeyIRI is safe here: SealClaim has already parsed the same hex successfully.
func mustKeyIRI(pubHex string) string {
	iri, err := KeyIRI(pubHex)
	if err != nil {
		return ""
	}
	return iri
}
