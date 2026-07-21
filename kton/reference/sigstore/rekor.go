// Package sigstore anchors DSSE-signed statements in the Sigstore **Rekor** transparency log,
// giving a tamper-evident, timestamped proof-of-existence - the "transparency log" the trust
// docs promise (docs/attestation.md). It COMPLEMENTS the Ed25519 signatures (attribution), it
// does not replace them. Because it makes network calls, it lives OUTSIDE the pure kernel: an
// optional trust-anchoring capability a cockpit invokes, never something `plankton record` needs.
//
// Verification is done natively (stdlib crypto only): the RFC 6962 Merkle inclusion proof is
// recomputed to the log root, and the Signed Entry Timestamp (SET) - an ECDSA-P256 signature by
// Rekor over the canonical entry bundle - is checked against Rekor's published public key. So an
// auditor can confirm "the public log holds exactly this entry, timestamped at T" without
// trusting our client.
package sigstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"kton.dev/plankton/core"
)

// ed25519FromVerifierPEM parses an SPKI PEM (as Rekor stores a dsse verifier / as we submit one) into
// its raw Ed25519 public key bytes, for comparing "the entry's signer" against "our record's signer".
func ed25519FromVerifierPEM(pemBytes []byte) ([]byte, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("verifier is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("verifier is not Ed25519")
	}
	return ek, nil
}

// VerifyBinds checks the log entry is actually ABOUT the submitted record - the check that makes an
// anchor meaningful. A genuine BUT UNRELATED entry, replayed by a hostile endpoint, passes VerifySET +
// VerifyInclusion (it is a real Rekor entry) yet is not YOUR record; without this the client would
// print "anchored" for a record honest Rekor rejected. Binds on: kind==dsse, the entry's payloadHash
// equals sha256 of this envelope's payload, and one of the entry's signature verifiers is this record's
// verifier key.
func (e *Entry) VerifyBinds(env core.Envelope, verifierPEM []byte) error {
	raw, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return fmt.Errorf("entry body base64: %w", err)
	}
	var b struct {
		Kind string `json:"kind"`
		Spec struct {
			PayloadHash struct {
				Value string `json:"value"`
			} `json:"payloadHash"`
			Signatures []struct {
				Verifier string `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("entry body json: %w", err)
	}
	if b.Kind != "dsse" {
		return fmt.Errorf("entry kind %q is not dsse", b.Kind)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("envelope payload base64: %w", err)
	}
	sum := sha256.Sum256(payload)
	if !strings.EqualFold(b.Spec.PayloadHash.Value, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("entry is about a DIFFERENT record: its payloadHash %s is not this record's payload hash %s (replayed / unrelated entry)", b.Spec.PayloadHash.Value, hex.EncodeToString(sum[:]))
	}
	mine, err := ed25519FromVerifierPEM(verifierPEM)
	if err != nil {
		return err
	}
	for _, s := range b.Spec.Signatures {
		pemBytes, derr := base64.StdEncoding.DecodeString(s.Verifier)
		if derr != nil {
			continue
		}
		if k, kerr := ed25519FromVerifierPEM(pemBytes); kerr == nil && bytes.Equal(k, mine) {
			return nil // the entry carries our record's verifier key
		}
	}
	return fmt.Errorf("entry does not carry this record's verifier key")
}

// DefaultRekorURL is the public Sigstore Rekor instance.
const DefaultRekorURL = "https://rekor.sigstore.dev"

// Ed25519VerifierPEM converts a raw Ed25519 public key to the SPKI PEM a Rekor `dsse` entry
// wants as a verifier (Rekor re-verifies the DSSE signature at submission).
func Ed25519VerifierPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Entry is a Rekor log entry (as created or fetched).
type Entry struct {
	UUID           string          `json:"uuid"`
	Body           string          `json:"body"` // base64 canonical entry body
	LogID          string          `json:"logID"`
	LogIndex       int64           `json:"logIndex"`
	IntegratedTime int64           `json:"integratedTime"`
	SET            string          `json:"signedEntryTimestamp"` // base64 ECDSA sig
	Inclusion      *InclusionProof `json:"inclusionProof,omitempty"`
}

// InclusionProof is the RFC 6962 Merkle audit path proving the entry is in the log.
type InclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

// --- Rekor REST shapes (only the fields we use) ---

type dsseProposed struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		ProposedContent struct {
			Envelope  string   `json:"envelope"`
			Verifiers []string `json:"verifiers"`
		} `json:"proposedContent"`
	} `json:"spec"`
}

type logEntryAnon struct {
	Body           string `json:"body"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	IntegratedTime int64  `json:"integratedTime"`
	Verification   struct {
		SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
		InclusionProof       *InclusionProof `json:"inclusionProof"`
	} `json:"verification"`
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// Anchor submits a DSSE envelope to Rekor as a `dsse` entry and returns the created log entry.
// Rekor re-verifies the DSSE signature against verifierPEM before accepting - so a successful
// anchor is itself third-party evidence the signature is valid.
func Anchor(rekorURL string, env core.Envelope, verifierPEM []byte) (*Entry, error) {
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	var pe dsseProposed
	pe.APIVersion = "0.0.1"
	pe.Kind = "dsse"
	pe.Spec.ProposedContent.Envelope = string(envBytes)
	pe.Spec.ProposedContent.Verifiers = []string{base64.StdEncoding.EncodeToString(verifierPEM)}
	body, err := json.Marshal(pe)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient().Post(rekorURL+"/api/v1/log/entries", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor POST %s: %s", resp.Status, string(raw))
	}
	return parseEntriesResponse(raw)
}

// GetByUUID fetches an entry by its UUID.
func GetByUUID(rekorURL, uuid string) (*Entry, error) {
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	resp, err := httpClient().Get(rekorURL + "/api/v1/log/entries/" + uuid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor GET %s: %s", resp.Status, string(raw))
	}
	return parseEntriesResponse(raw)
}

// parseEntriesResponse decodes the {uuid: entry} map Rekor returns.
func parseEntriesResponse(raw []byte) (*Entry, error) {
	var m map[string]logEntryAnon
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode rekor response: %w (%s)", err, string(raw))
	}
	for uuid, le := range m {
		e := &Entry{
			UUID:           uuid,
			Body:           le.Body,
			LogID:          le.LogID,
			LogIndex:       le.LogIndex,
			IntegratedTime: le.IntegratedTime,
			SET:            le.Verification.SignedEntryTimestamp,
			Inclusion:      le.Verification.InclusionProof,
		}
		return e, nil
	}
	return nil, fmt.Errorf("rekor returned no entry")
}

// PublicKey fetches Rekor's ECDSA public key (PEM) used to sign the SET.
func PublicKey(rekorURL string) (*ecdsa.PublicKey, error) {
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	resp, err := httpClient().Get(rekorURL + "/api/v1/log/publicKey")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	pemBytes, _ := io.ReadAll(resp.Body)
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("rekor publicKey: not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rekor publicKey: not ECDSA")
	}
	return ec, nil
}

// VerifySET checks Rekor's Signed Entry Timestamp: an ECDSA-P256 signature over the canonical
// JSON bundle {body, integratedTime, logID, logIndex}. This proves Rekor attested this exact
// entry at integratedTime, independent of the inclusion proof.
func (e *Entry) VerifySET(rekorPub *ecdsa.PublicKey) error {
	if e.SET == "" {
		return fmt.Errorf("entry has no signedEntryTimestamp")
	}
	sig, err := base64.StdEncoding.DecodeString(e.SET)
	if err != nil {
		return fmt.Errorf("SET base64: %w", err)
	}
	// The SET is signed over the canonical (RFC 8785) JSON of exactly these four fields.
	bundle := map[string]any{
		"body":           e.Body,
		"integratedTime": e.IntegratedTime,
		"logID":          e.LogID,
		"logIndex":       e.LogIndex,
	}
	canon, err := core.CanonValue(bundle)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canon)
	if !ecdsa.VerifyASN1(rekorPub, digest[:], sig) {
		return fmt.Errorf("SET signature does not verify against Rekor's public key")
	}
	return nil
}

// VerifyInclusion recomputes the RFC 6962 Merkle root from the entry's leaf and audit path and
// checks it equals the proof's rootHash - proving the entry is committed in the log at rootHash.
func (e *Entry) VerifyInclusion() error {
	if e.Inclusion == nil {
		return fmt.Errorf("entry has no inclusion proof")
	}
	leaf, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return fmt.Errorf("body base64: %w", err)
	}
	// RFC 6962 leaf hash: SHA256(0x00 || leaf).
	h := sha256.Sum256(append([]byte{0x00}, leaf...))
	computed, err := rootFromInclusionProof(h[:], e.Inclusion.LogIndex, e.Inclusion.TreeSize, e.Inclusion.Hashes)
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(e.Inclusion.RootHash)
	if err != nil {
		return fmt.Errorf("rootHash hex: %w", err)
	}
	if !bytes.Equal(computed, want) {
		return fmt.Errorf("inclusion proof does not reconstruct the root (got %x, want %s)", computed, e.Inclusion.RootHash)
	}
	return nil
}

// rootFromInclusionProof applies the RFC 6962 §2.1.1 audit path (the Trillian reference
// algorithm): fn = leaf index, sn = last index (treeSize-1), consumed exactly by the proof.
func rootFromInclusionProof(leafHash []byte, index, size int64, proofHex []string) ([]byte, error) {
	if index < 0 || index >= size {
		return nil, fmt.Errorf("index %d out of range for tree size %d", index, size)
	}
	fn, sn := index, size-1
	r := leafHash
	for _, ph := range proofHex {
		sib, err := hex.DecodeString(ph)
		if err != nil {
			return nil, fmt.Errorf("proof hash hex: %w", err)
		}
		if sn == 0 {
			return nil, fmt.Errorf("inclusion proof too long")
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(sib, r) // sibling is on the left
			if fn&1 == 0 {
				for fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = hashChildren(r, sib) // sibling is on the right
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, fmt.Errorf("inclusion proof too short")
	}
	return r, nil
}

// hashChildren = SHA256(0x01 || left || right) (RFC 6962 interior node).
func hashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}
