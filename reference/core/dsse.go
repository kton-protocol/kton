package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// KeyIDHex is the display keyid of an Ed25519 public key: the first 16 hex chars of sha256(pubkey).
func KeyIDHex(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

// VerifiedSignerKeyID returns the keyid of the first supplied public key whose signature actually
// verifies this envelope, or "" if none do. This is AUTHENTICATED attribution: it follows the
// cryptographic signature, NOT the envelope's self-declared Signatures[0].KeyID - which any relabeler
// can set to a victim's keyid while leaving the real signature intact. Every export/display/gate path
// that surfaces "who signed this" must derive identity from HERE (given the trusted keys), so a
// tampered attribution is dropped rather than presented as established (cold-session systemic finding).
func VerifiedSignerKeyID(e Envelope, keys []ed25519.PublicKey) string {
	for _, pub := range keys {
		if ok, err := e.Verify(pub); ok && err == nil {
			return KeyIDHex(pub)
		}
	}
	return ""
}

// PayloadType is the DSSE payload type for in-toto statements (spec §8).
const PayloadType = "application/vnd.in-toto+json"

// PredicateFoton is the in-toto predicateType the kernel records: a reproducible result
// (spec §6.6). Attestations ABOUT results (qualification verdicts, environment-qualification,
// reviews, votes) are signed claims in the nekton layer - not plankton. See ../../nekton and
// DECISIONS §1–§5 (the reproducible/attestable cut).
const PredicateFoton = "https://kton.dev/foton/v0"

// SpecVersion is the exact spec revision an authoring tool stamps into a foton's predicate
// (`predicate.specVersion`). It is CARRIED, not covered: the foton id projects only
// inputs/outputs/protocol (see foton.go FotonID), so this field is signed and attested but never
// changes the foton id or action key. The `/v0` in the predicateType is the breaking-change contract
// marker; this is the finer revision, for provenance/audit while the spec is pre-1.0. (Claims carry
// no equivalent: a claim id is the hash of its whole statement, so it has no carried region - claims
// are versioned by their `claim/v0` predicateType.)
const SpecVersion = "0.1"

// Subject is an in-toto subject: a named artifact identified by digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
	URI    []string          `json:"uri,omitempty"` // CARRIED (spec §6.1): where the bytes may be fetched; NOT part of the foton id
}

// Statement is an in-toto v1 Statement (spec §6.6).
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Envelope is a DSSE envelope (spec §8).
type Envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// HasSignature reports whether the envelope carries at least one SUBSTANTIVE signature (a non-empty
// sig). Ingest is presence-gated, not verification-gated (verifying is `verify`), but a signatures
// array whose only entry has an empty/absent sig is not a signed record - so the ingest gate checks
// signature bytes are present, not merely that the array is non-empty (cold-session finding).
func (e Envelope) HasSignature() bool {
	for _, s := range e.Signatures {
		if s.Sig != "" {
			return true
		}
	}
	return false
}

// PAE computes the DSSE Pre-Authentication Encoding (spec §8).
func PAE(payloadType string, payload []byte) []byte {
	pt := []byte(payloadType)
	out := []byte("DSSEv1 ")
	out = append(out, []byte(strconv.Itoa(len(pt)))...)
	out = append(out, ' ')
	out = append(out, pt...)
	out = append(out, ' ')
	out = append(out, []byte(strconv.Itoa(len(payload)))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// PayloadBytes returns the base64-decoded payload (the literal signed statement bytes).
func (e Envelope) PayloadBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Payload)
}

// Verify reports whether ANY of the envelope's signatures verifies against an Ed25519 public
// key. An envelope may legitimately carry several signatures (e.g. multi-party sign-off); a
// single malformed signature is skipped rather than failing the whole envelope.
func (e Envelope) Verify(pub ed25519.PublicKey) (bool, error) {
	if len(e.Signatures) == 0 {
		return false, fmt.Errorf("envelope has no signatures")
	}
	payload, err := e.PayloadBytes()
	if err != nil {
		return false, fmt.Errorf("payload base64: %w", err)
	}
	msg := PAE(e.PayloadType, payload)
	for _, s := range e.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			return true, nil
		}
	}
	return false, nil
}

// Statement decodes the envelope payload into a Statement (no re-canonicalization).
func (e Envelope) Statement() (*Statement, error) {
	payload, err := e.PayloadBytes()
	if err != nil {
		return nil, err
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ParsePublicKeyHex loads a raw (32-byte hex) Ed25519 public key.
func ParsePublicKeyHex(h string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte key, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// fotonPredicate is the predicate body of a foton/v0 statement.
type fotonPredicate struct {
	Inputs   []Subject `json:"inputs"`
	Protocol Protocol  `json:"protocol"`
}

// ToFoton extracts a Foton from a foton/v0 Statement (subject=outputs, predicate.inputs).
func (st *Statement) ToFoton() (*Foton, error) {
	if st.PredicateType != PredicateFoton {
		return nil, fmt.Errorf("not a foton statement: %s", st.PredicateType)
	}
	var p fotonPredicate
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, err
	}
	f := &Foton{Protocol: p.Protocol}
	for _, s := range st.Subject {
		f.Outputs = append(f.Outputs, subjectToRef(s))
	}
	for _, s := range p.Inputs {
		f.Inputs = append(f.Inputs, subjectToRef(s))
	}
	return f, nil
}

func subjectToRef(s Subject) FileRef {
	// in-toto subject `name` carries the file's relative path (Bazel/in-toto convention).
	// Normalize the digest to canonical lowercase (SPEC §5.1) so an uppercase-hex hash does not
	// split a foton's identity/index from the same digest written in the canonical form.
	hash := "sha256:" + s.Digest["sha256"]
	if norm, ok := NormalizeContentHash(hash); ok {
		hash = norm
	}
	return FileRef{Hash: hash, Path: s.Name, URI: s.URI}
}
