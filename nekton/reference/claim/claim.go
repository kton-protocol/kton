// Package claim implements the nekton kernel's one logical type: the signed Claim, carried
// as an in-toto Statement in a DSSE envelope (kton SPEC §7.2–§7.3). It reuses plankton's shared
// `core` for canonical JSON, hashing, and DSSE - the one allowed nekton -> plankton dependency.
// The kernel treats `predicate`/`context` as OPAQUE terms; it never interprets vocabulary.
package claim

import (
	"encoding/json"
	"fmt"
	"time"

	"kton.dev/plankton/core"
)

// PredicateType is the in-toto predicateType for a nekton claim (SPEC §7.3).
const PredicateType = "https://kton.dev/claim/v0"

// ScopePredicateType marks a seed (scope genesis) Statement (SPEC §7.4).
const ScopePredicateType = "https://kton.dev/scope/v0"

// Ref is a reference to a thing a claim is about or points at: a content hash and/or a URI
// (SPEC §7.1). At least one MUST be present.
type Ref struct {
	Hash string `json:"hash,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// Key is the string a Ref indexes under (hash preferred, else uri).
// hashOrURIKey normalizes a hash to canonical lowercase (SPEC §5.1) so the same digest resolves to
// one index key; a URI (or an empty/malformed hash) passes through unchanged.
func hashOrURIKey(hash, uri string) string {
	if hash != "" {
		if norm, ok := core.NormalizeContentHash(hash); ok {
			return norm
		}
		return hash
	}
	return uri
}

func (r Ref) Key() string { return hashOrURIKey(r.Hash, r.URI) }

// TermRef is an opaque relation/context term: a content-addressed definition and/or a
// vocabulary IRI (SPEC §7.1). The kernel stores and indexes it but never validates it.
type TermRef struct {
	Hash string `json:"hash,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// Key is the string a TermRef indexes under.
func (t TermRef) Key() string { return hashOrURIKey(t.Hash, t.URI) }

// Subject is an in-toto subject: a hash (digest) and/or a URI, optionally named (SPEC §7.3).
type Subject struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
	URI    string            `json:"uri,omitempty"`
}

// Key is the string a subject resolves under: "sha256:<hex>" if digested, else the URI. The digest
// is normalized to canonical lowercase (SPEC §5.1) so a claim about "sha256:ABC..." indexes and
// resolves under the same key as one about "sha256:abc..." - without this a claim about a subject is
// invisible to a consumer resolving the same digest in the canonical form (cold-session finding).
func (s Subject) Key() string {
	if h := s.Digest["sha256"]; h != "" {
		if norm, ok := core.NormalizeContentHash("sha256:" + h); ok {
			return norm
		}
		return "sha256:" + h
	}
	return s.URI
}

// Statement is the in-toto v1 wire form of a claim (SPEC §7.3). Predicate stays raw so the
// kernel can canonicalize/index it without imposing a schema on the vocabulary.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
	// Genesis is parsed ONLY to reject it: genesis is a structural flag that lives INSIDE a scope/v0
	// predicate (SPEC §7.4). A top-level `genesis` is never valid and must not be a back door to the
	// scope-minting guard, which otherwise inspects only predicate.genesis (cold-session finding).
	Genesis bool `json:"genesis,omitempty"`
}

// ObjOrLit is a claim `object`: either a Ref (hash/uri) or a Literal (value + optional
// datatype). Only Ref-shaped objects (hash/uri) are indexable; literals are stored, not keyed.
type ObjOrLit struct {
	Hash     string   `json:"hash,omitempty"`
	URI      string   `json:"uri,omitempty"`
	ID       string   `json:"id,omitempty"` // an identity reference: a DID, a key IRI, an OCI/other URI
	Value    any      `json:"value,omitempty"`
	Datatype *TermRef `json:"datatype,omitempty"`
}

// Key is the indexable key of an object; empty for a bare literal. An object given as {"id": X} - the
// most common shape across the vocabulary (a DID, a key IRI, a pinned OCI image, a spectrum IRI) - is
// a real reference and MUST be indexed, or `nekton by object X` silently finds none of those claims
// (they render fine but were un-indexed: the id field was neither hash nor uri, so Key() was empty).
func (o *ObjOrLit) Key() string {
	if o == nil {
		return ""
	}
	if k := hashOrURIKey(o.Hash, o.URI); k != "" {
		return k
	}
	if norm, ok := core.NormalizeContentHash(o.ID); ok {
		return norm // an id that is actually a content hash normalizes like any other
	}
	return o.ID
}

// Predicate is the parsed claim body - the fields the kernel indexes (SPEC §7.2) and the
// structural scope/seed/chain fields it enforces (SPEC §7.4). Unknown keys are ignored:
// the kernel is agnostic to the rest of the vocabulary.
type Predicate struct {
	Predicate TermRef   `json:"predicate"`
	Object    *ObjOrLit `json:"object,omitempty"`
	Context   *TermRef  `json:"context,omitempty"`
	By        string    `json:"by"`
	When      string    `json:"when"`
	Why       string    `json:"why,omitempty"`
	Evidence  []Ref     `json:"evidence,omitempty"`

	// Structural scope/seed/chain fields (SPEC §7.4) - the only grammar the kernel enforces.
	Scope       string   `json:"scope,omitempty"`
	Prev        string   `json:"prev,omitempty"`
	Parent      *Ref     `json:"parent,omitempty"`
	Responsible []string `json:"responsible,omitempty"`
	Genesis     bool     `json:"genesis,omitempty"`
}

// ParseEnvelope decodes a DSSE envelope's payload into a claim Statement, returning the raw
// (canonical, signed) payload bytes too - the bytes the claim-id is computed over.
func ParseEnvelope(env core.Envelope) (*Statement, []byte, error) {
	pb, err := env.PayloadBytes()
	if err != nil {
		return nil, nil, err
	}
	// CLASS BOUNDARY: the payload MUST be valid canonical JSON. This is the one gate every path goes
	// through (ingest, verify, show, export), so a payload with a duplicate key or a >2^53 integer -
	// which CanonJSON rejects but ClaimID's raw-bytes fallback would otherwise hash and ingest anyway -
	// is refused everywhere, not just where CanonJSON happens to be called. Equal id then always means
	// equal content-as-read (cold-session canonicalization sibling-path finding).
	if _, err := core.CanonJSON(pb); err != nil {
		return nil, nil, fmt.Errorf("claim payload is not valid canonical JSON: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(pb, &st); err != nil {
		return nil, nil, err
	}
	return &st, pb, nil
}

// ParsePredicate parses the claim body for indexing/enforcement.
func (st *Statement) ParsePredicate() (*Predicate, error) {
	var p Predicate
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// IsSeed reports whether a Statement opens a scope. This is a STRUCTURAL test (SPEC §7.4): the
// predicateType must be the scope type. `genesis:true` on an ordinary claim/v0 statement does
// NOT make a seed - otherwise anyone could mint scope identities and root fake chains.
func (st *Statement) IsSeed() bool {
	return st.PredicateType == ScopePredicateType
}

// ClaimID is the content address of a claim: sha256 of the CANONICAL claim Statement
// (signatures live in the envelope and are excluded). Canonicalizing BEFORE hashing is what
// makes two registries that received the same logical claim with byte-different-but-JSON-equal
// payloads coincide by id - the conflict-free set-union merge invariant (SPEC §7.2, §12). The
// payload is an already-parsed Statement, so canonicalization does not fail in practice; the raw
// fallback only guards a pathological input.
func ClaimID(payload []byte) string {
	c, err := core.CanonJSON(payload)
	if err != nil {
		// A non-canonical payload (duplicate key / imprecise integer) has NO valid claim id. ParseEnvelope
		// refuses it before this point; as a defensive last resort, derive a poisoned id from a marker so
		// it can NEVER collide with a real (canonical) claim id - the raw-bytes fallback used to hand it a
		// normal-looking id and let it ingest (cold-session sibling-path finding).
		return core.HashBytes(append([]byte("\x00kton:non-canonical\x00"), payload...))
	}
	return core.HashBytes(c)
}

// Validate enforces the required-field grammar (SPEC §7.2): a non-seed claim MUST carry a subject,
// a predicate term, a signer, and a timestamp. Seeds are governed by the structural §7.4 fields
// instead and are exempt here.
func (st *Statement) Validate(p *Predicate) error {
	if st.IsSeed() {
		return nil
	}
	if len(st.Subject) == 0 {
		return fmt.Errorf("claim has no subject (SPEC §7.2 requires one)")
	}
	if p == nil || p.Predicate.Key() == "" {
		return fmt.Errorf("claim has no predicate term (SPEC §7.2)")
	}
	if p.By == "" || p.When == "" {
		return fmt.Errorf("claim missing required by/when (SPEC §7.2)")
	}
	// `when` is a timestamp, not free text: it MUST be an RFC 3339 instant (SPEC §7.2). Unvalidated, a
	// non-RFC3339 garbage value signed and displayed as authoritative just like a real timestamp
	// (cold-session time-freshness F1). Reject a malformed instant at the one ingest gate every claim
	// passes. NOTE: a well-formed but far-future/backdated `when` is still ACCEPTED here - the substrate
	// is monotone and has no supersession-aware read; semantic freshness ("is this the LATEST, is the
	// signer's key still valid?") is an out-of-band concern (anchoring + a latest-pointer), documented as
	// a boundary, not enforced by this format check.
	if _, err := time.Parse(time.RFC3339, p.When); err != nil {
		return fmt.Errorf("claim `when` is not an RFC 3339 timestamp (SPEC §7.2): %q", p.When)
	}
	return nil
}

// CanonicalStatement returns the canonical bytes of a bare Statement (for a claim id without
// an envelope).
func CanonicalStatement(st any) ([]byte, error) {
	b, err := core.CanonValue(st)
	if err != nil {
		return nil, fmt.Errorf("canonicalize statement: %w", err)
	}
	return b, nil
}
