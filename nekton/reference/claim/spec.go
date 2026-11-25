package claim

// spec.go is the authoring front end: the small JSON a cockpit hands in, and the one function
// that turns it into the canonical in-toto Statement bytes that get signed (SPEC §7.3).
//
// This logic used to live in `package main` of cmd/nekton, which meant only the CLI could author
// a claim. It moved here so that EVERY authoring path - the CLI, and the browser via the WASM
// kernel - assembles the payload through the same code. That matters more than tidiness: a claim
// signed in a browser must be byte-identical to the same claim signed by the CLI, or the two get
// different claim ids and stop deduplicating in the federated union (SPEC §7.2, §12). One
// implementation is the only way to guarantee that.
//
// Signing itself is deliberately NOT here: this package produces the bytes to sign and reassembles
// the result, so a caller holding a non-extractable browser key (WebCrypto) can sign without ever
// exposing key material to Go.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"kton.dev/plankton/core"
)

// SubjectSpec is one subject in a claim spec: a hash and/or a uri, optionally named.
type SubjectSpec struct {
	Name string `json:"name,omitempty"`
	Hash string `json:"hash,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// Spec is the small JSON a cockpit hands to `nekton claim`. Two ways to give the body:
//   - PredicateBody: the exact predicate object (byte-precise; used to reproduce vectors), or
//   - the convenience fields (predicate/object/context/by/when/why/evidence) assembled for you.
type Spec struct {
	Subject       []SubjectSpec  `json:"subject"`
	PredicateType string         `json:"predicateType"` // default nekton claim/v0
	PredicateBody map[string]any `json:"predicateBody"` // passthrough (exact)

	Predicate string         `json:"predicate"` // relation term IRI (convenience)
	Object    map[string]any `json:"object,omitempty"`
	Context   string         `json:"context,omitempty"`
	By        string         `json:"by,omitempty"`
	When      string         `json:"when,omitempty"`
	Why       string         `json:"why,omitempty"`
	Evidence  []any          `json:"evidence,omitempty"`

	// Structural scope/chain fields (SPEC §7.4): a scoped claim names its scope (a seed's id) and
	// its prev (the previous claim in the scope, or the seed for the first link). Empty = unscoped.
	Scope string `json:"scope,omitempty"`
	Prev  string `json:"prev,omitempty"`
}

// ParseSpec decodes claim-spec JSON.
//
// UseNumber so a numeric object value keeps its EXACT literal (a json.Number) instead of being
// truncated through float64 before signing - otherwise authoring would sign 9007199254740992 when
// the author typed ...993, and CanonValue (which rejects an imprecise integer) never sees the real
// value. With json.Number the big int survives to canonicalization and is REJECTED, so the signer
// is told rather than silently signing a different number.
// DisallowUnknownFields because encoding/json otherwise DROPS a field it does not know, in
// silence. The trap that motivated this: a subject is written `{"hash":"sha256:..."}` on the way in
// and rendered `{"digest":{"sha256":"..."}}` on the way out (SPEC §7.3, the in-toto form). Anyone
// who reads a signed statement and reasons backwards writes `digest` - and got a claim whose subject
// was `{}`. It signed, it verified, it indexed, and it was about nothing. Not one word of warning.
//
// A misspelling in a signed document must be an error, not an omission. This also catches every
// other typo (`predicat`, `subjekt`, a misplaced `when`) at the one place a human writes the file.
func ParseSpec(raw []byte) (Spec, error) {
	// On the RAW bytes first, because decoding destroys the evidence: Go keeps the LAST of a
	// duplicate name and stops at the end of the first document. DisallowUnknownFields catches a
	// MISSPELLED field; it does not catch a REPEATED known one, so `"why":"first","why":"second"`
	// was decoded to "second" and signed without complaint.
	if err := core.CheckJSONDocument(raw); err != nil {
		return Spec{}, fmt.Errorf("claim spec: %w", err)
	}
	var spec Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return Spec{}, specFieldError(err)
	}
	return spec, nil
}

// specFieldError turns encoding/json's terse "unknown field" into something that says what to
// write instead, for the spellings a reader of the SIGNED form would reasonably reach for.
func specFieldError(err error) error {
	msg := err.Error()
	const unknown = `json: unknown field "`
	i := strings.Index(msg, unknown)
	if i < 0 {
		return err
	}
	field := msg[i+len(unknown):]
	if j := strings.IndexByte(field, '"'); j >= 0 {
		field = field[:j]
	}
	switch field {
	case "digest":
		return fmt.Errorf("a claim spec names a subject with `hash` (\"sha256:<hex>\"), not `digest`. "+
			"`digest: {sha256: ...}` is the in-toto form of the SIGNED statement (SPEC §7.3); the spec "+
			"you hand to `nekton claim` uses the shorter `hash`. Writing `digest` here used to be "+
			"accepted and silently produced a claim about NOTHING: %w", err)
	case "subjects", "subj":
		return fmt.Errorf("the field is `subject` (an array), not %q: %w", field, err)
	default:
		return fmt.Errorf("%w - a claim spec field this build does not know is refused rather than "+
			"dropped, because a dropped field is signed away in silence", err)
	}
}

// BareHash strips a multihash-style "sha256:" prefix, leaving the bare hex digest that the
// in-toto subject `digest` map expects.
func BareHash(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[i+1:]
	}
	return h
}

// normHash folds a content hash to canonical lowercase (SPEC §5.1) BEFORE it enters the signed
// payload, so a claim authored with an uppercase/mixed-case digest gets the SAME claim id as the
// canonical form - making the §12 conflict-free union dedup and keeping the wire form §5.1-conformant.
func normHash(h string) string {
	if n, ok := core.NormalizeContentHash(h); ok {
		return n
	}
	return h
}

// SubjectsOf renders subject specs into the in-toto `subject` array form (SPEC §7.3),
// normalizing any content hash to canonical lowercase on the way in.
func SubjectsOf(ss []SubjectSpec) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		m := map[string]any{}
		if s.Name != "" {
			m["name"] = s.Name
		}
		if s.Hash != "" {
			m["digest"] = map[string]any{"sha256": BareHash(normHash(s.Hash))}
		}
		if s.URI != "" {
			m["uri"] = s.URI
		}
		out = append(out, m)
	}
	return out
}

// normHashField lowercases a "hash" member of an object/evidence map in place (SPEC §5.1).
func normHashField(m map[string]any) {
	if h, ok := m["hash"].(string); ok {
		m["hash"] = normHash(h)
	}
}

// PercentEncodingValid reports whether every '%' in s starts a %XX escape (two hex digits), as an
// IRI requires (RFC 3987). The empty string is valid. The template loader, the signer and the
// per-record projection use this one rule, so they agree on what can be written.
func PercentEncodingValid(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && !(i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2])) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// IRIText reports whether s can stand in an IRI position exactly as written: valid UTF-8, every
// '%' starting a %XX escape, and no character the N-Quads writer would otherwise have to
// percent-encode (a control, space, C1, U+2028/U+2029, or one of <>"{}|^`\). Encoding is no option:
// "a b" would become "a%20b", the IRI another claim may name genuinely (#268 T1, kton-review N2 on
// #314). The signer and the per-record projection use this one rule.
func IRIText(s string) bool {
	if !utf8.ValidString(s) || !PercentEncodingValid(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || strings.ContainsRune("<>\"{}|^`\\", r) {
			return false
		}
	}
	return true
}

// checkIRIs refuses a claim whose predicate, context or IRI-shaped subject uri is no IRIText, for a body built
// from the convenience fields and for a PredicateBody alike, before it is signed. Such a claim's
// projection is refused by a conforming store (kton-cockpit 25.11.) or would merge two IRIs into one;
// a signed claim cannot be fixed later. Object values are not checked: a string there is a value, and
// the projection keeps one that is no valid IRI as a literal.
// hasScheme reports whether s starts with an RFC 3986 scheme and ':' (a letter, then letters,
// digits, + - .).
func hasScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return false
	}
	for j, c := range s[:i] {
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (j == 0 || !(c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return true
}

func checkIRIs(body map[string]any, subjects []SubjectSpec) error {
	for _, k := range []string{"predicate", "context"} {
		m, _ := body[k].(map[string]any)
		if u, _ := m["uri"].(string); !IRIText(u) {
			return fmt.Errorf("%s %q is no IRI as written: a space, a control character, one of "+
				"<>\"{}|^`\\, or a '%%' that starts no %%XX escape (write %%25 for a literal '%%')", k, u)
		}
	}
	// A subject uri is a string (SPEC §7.1), and one that is no IRI at all ("kton video") stays
	// signable; the projection names it as unprojectable. One that starts with a scheme claims to be
	// an IRI, and then must be one as written.
	for _, sub := range subjects {
		if hasScheme(sub.URI) && !IRIText(sub.URI) {
			return fmt.Errorf("subject uri %q is no IRI as written: a space, a control character, one of "+
				"<>\"{}|^`\\, or a '%%' that starts no %%XX escape", sub.URI)
		}
	}
	return nil
}

// BuildPredicate assembles the predicate body from the convenience fields (used when
// PredicateBody is absent). Keys omitted when empty; canonicalization sorts them.
func (spec Spec) BuildPredicate() (map[string]any, error) {
	if spec.PredicateBody != nil {
		return spec.PredicateBody, nil
	}
	if spec.Predicate == "" {
		return nil, fmt.Errorf("claim spec needs `predicate` (relation IRI) or `predicateBody`")
	}
	// TEMPLATE/ALIAS TRUST: what a claim MEANS must not depend on the READER's mutable alias file. A
	// predicate stored as a full IRI ("https://…") or a prefixed CURIE ("pav:createdBy") names its own
	// vocabulary; a BARE TERM ("reviewedBy") is maximally ambiguous - any reader's term map resolves it
	// differently, and a MITM'd alias file silently changes its meaning. Refuse to sign a bare term
	// (annotate has already run the alias file through `resolve` and ECHOES the result). A CURIE's prefix
	// is still reader-resolved; pin the prefix map / prefer full IRIs for a regulated vocabulary.
	if !strings.Contains(spec.Predicate, ":") {
		return nil, fmt.Errorf("predicate %q is a bare term with no vocabulary - refusing to sign an ambiguous relation whose meaning depends on the reader's alias file; use a full IRI or a prefixed CURIE", spec.Predicate)
	}
	if spec.By == "" || spec.When == "" {
		return nil, fmt.Errorf("claim spec needs `by` and `when`")
	}
	body := map[string]any{
		"predicate": map[string]any{"uri": spec.Predicate},
		"by":        spec.By,
		"when":      spec.When,
	}
	if spec.Object != nil {
		normHashField(spec.Object)
		body["object"] = spec.Object
	}
	if spec.Context != "" {
		body["context"] = map[string]any{"uri": spec.Context}
	}
	if spec.Why != "" {
		body["why"] = spec.Why
	}
	if len(spec.Evidence) > 0 {
		for _, e := range spec.Evidence {
			if m, ok := e.(map[string]any); ok {
				normHashField(m)
			}
		}
		body["evidence"] = spec.Evidence
	}
	if spec.Scope != "" {
		body["scope"] = spec.Scope
	}
	if spec.Prev != "" {
		body["prev"] = spec.Prev
	}
	return body, nil
}

// StatementPayload canonicalizes a Spec into the in-toto Statement bytes that get signed
// (SPEC §7.3). These bytes are both the DSSE payload and the preimage of the claim id.
func StatementPayload(spec Spec) ([]byte, error) {
	body, err := spec.BuildPredicate()
	if err != nil {
		return nil, err
	}
	if err := checkIRIs(body, spec.Subject); err != nil {
		return nil, err
	}
	pt := spec.PredicateType
	if pt == "" {
		pt = PredicateType
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       SubjectsOf(spec.Subject),
		"predicateType": pt,
		"predicate":     body,
	}
	return core.CanonValue(st)
}

// SigningInput returns the canonical payload and the exact bytes a signer must sign over
// (the DSSE Pre-Authentication Encoding). Split out from Seal so that a caller whose private key
// is unexportable - a WebCrypto Ed25519 key in a browser - can do the raw signature itself.
func SigningInput(spec Spec) (payload, toSign []byte, err error) {
	payload, err = StatementPayload(spec)
	if err != nil {
		return nil, nil, err
	}
	return payload, core.PAE(core.PayloadType, payload), nil
}

// Seal reassembles a signature made over SigningInput's `toSign` into a DSSE envelope, and
// returns it with the claim id. It VERIFIES the signature against pub before returning: a caller
// that mismatched key and signature learns here, not when a registry later rejects the record.
func Seal(payload, sig []byte, pub ed25519.PublicKey) (core.Envelope, string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return core.Envelope{}, "", fmt.Errorf("expected a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(pub))
	}
	if !ed25519.Verify(pub, core.PAE(core.PayloadType, payload), sig) {
		return core.Envelope{}, "", fmt.Errorf("signature does not verify against the supplied public key")
	}
	env := core.Envelope{
		PayloadType: core.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
	}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(pub),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	})
	return env, ClaimID(payload), nil
}

// SignWith is the whole authoring path for a caller that HOLDS the private key (the CLI).
// Browser callers use SigningInput + Seal instead.
func SignWith(spec Spec, priv ed25519.PrivateKey) (core.Envelope, string, error) {
	payload, toSign, err := SigningInput(spec)
	if err != nil {
		return core.Envelope{}, "", err
	}
	return Seal(payload, ed25519.Sign(priv, toSign), priv.Public().(ed25519.PublicKey))
}
