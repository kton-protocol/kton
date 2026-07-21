package main

// author.go is the write side: generate a signing identity (keygen) and author + sign a
// claim (claim). nekton, like plankton, does not decide whom to trust - it lets a key holder
// produce the signed claims it will store, verify, and federate. The wire form is byte-compatible
// with plankton's DSSE (shared `core`: canonical JSON + PAE + Ed25519), so the same trust
// tooling applies to both layers.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// keyidHex: first 16 hex chars of sha256(rawPublicKey) - identical to plankton (shared identity).
func keyidHex(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

// keyidOf resolves a .pub/.key file, a raw hex public key, a private-seed .key, or an existing 16-hex
// keyid to the keyid shown as `by=key:<id>`. A private .key (32-byte seed) and a .pub (32-byte public
// key) are both 64 hex; they are told apart by the ".key" suffix (a raw hex string is treated as a pubkey).
func keyidOf(s string) (string, error) {
	isKey := strings.HasSuffix(s, ".key")
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	txt = strings.TrimSpace(txt)
	if len(txt) == 16 { // already a keyid
		return txt, nil
	}
	raw, err := hex.DecodeString(txt)
	if err != nil {
		return "", fmt.Errorf("not a key: expected a .pub/.key file or hex public key, got %q", s)
	}
	if isKey && len(raw) == ed25519.SeedSize {
		return keyidHex(ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)), nil
	}
	if len(raw) == ed25519.PublicKeySize {
		return keyidHex(ed25519.PublicKey(raw)), nil
	}
	return "", fmt.Errorf("not an Ed25519 public key or .key seed: %q", s)
}

func keygen(name string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(name+".key", []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(name+".pub", []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return err
	}
	fmt.Printf("keypair %s  keyid=%s\n", name, keyidHex(pub))
	return nil
}

// loadPubArg accepts a public key as EITHER a .pub file path OR the hex string itself
// (cycle-1 finding: users pasted `$(cat key.pub)` into the "<pubkey.hex>" slot).
func loadPubArg(s string) (ed25519.PublicKey, error) {
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	return core.ParsePublicKeyHex(strings.TrimSpace(txt))
}

// keyidFromArg normalizes a signer argument to a keyid: it accepts a 16-hex keyid as-is, or a
// .pub file / 64-hex public key which it hashes to the keyid (cycle-1 finding: `by signer`
// silently returned nothing when handed a public key instead of the keyid).
func keyidFromArg(s string) string {
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	txt = strings.TrimSpace(txt)
	if len(txt) == 16 {
		return txt
	}
	if pub, err := core.ParsePublicKeyHex(txt); err == nil {
		return keyidHex(pub)
	}
	return strings.TrimSpace(s)
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("expected %d-byte seed, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// signingKey returns the signing identity: the key at keyPath, or - when keyPath is empty - a fresh
// EPHEMERAL key. Signing is mandatory, but handing over a persistent key is not: an unnamed session
// signs with a throwaway identity, so which model/agent authored the claim is unlinkable (anonymity
// by default). Persistent attribution is opt-in via --sign; a durable, identity-bearing signature is
// a cockpit concern (kton: Sigstore/OIDC), not a kernel one.
func signingKey(keyPath string) (ed25519.PrivateKey, bool, error) {
	if keyPath != "" {
		p, err := loadPriv(keyPath)
		return p, false, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, true, err
}

// subjSpec is one subject in a claim spec: a hash and/or a uri, optionally named.
type subjSpec struct {
	Name string `json:"name,omitempty"`
	Hash string `json:"hash,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// claimSpec is the small JSON a cockpit hands to `nekton claim`. Two ways to give the body:
//   - predicateBody: the exact predicate object (byte-precise; used to reproduce vectors), or
//   - the convenience fields (predicate/object/context/by/when/why/evidence) assembled for you.
type claimSpec struct {
	Subject       []subjSpec     `json:"subject"`
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

func bareHash(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[i+1:]
	}
	return h
}

// normHash folds a content hash to canonical lowercase (SPEC §5.1) BEFORE it enters the signed
// payload, so a claim authored with an uppercase/mixed-case digest gets the SAME claim id as the
// canonical form - making the §12 conflict-free union dedup and keeping the wire form §5.1-conformant
// (cold-session finding: normalizing only the index left case-variant claims with distinct ids).
func normHash(h string) string {
	if n, ok := core.NormalizeContentHash(h); ok {
		return n
	}
	return h
}

func subjectsOf(ss []subjSpec) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		m := map[string]any{}
		if s.Name != "" {
			m["name"] = s.Name
		}
		if s.Hash != "" {
			m["digest"] = map[string]any{"sha256": bareHash(normHash(s.Hash))}
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

// buildPredicate assembles the predicate body from the convenience fields (used when
// predicateBody is absent). Keys omitted when empty; canonicalization sorts them.
func (spec claimSpec) buildPredicate() (map[string]any, error) {
	if spec.PredicateBody != nil {
		return spec.PredicateBody, nil
	}
	if spec.Predicate == "" {
		return nil, fmt.Errorf("claim spec needs `predicate` (relation IRI) or `predicateBody`")
	}
	// TEMPLATE/ALIAS TRUST: what a claim MEANS must not depend on the READER's mutable alias file. A
	// predicate stored as a full IRI ("https://…") or a prefixed CURIE ("pav:reviewedBy") names its own
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

// authorClaim builds an in-toto Statement per SPEC §7.3, signs a DSSE envelope, and writes it.
func authorClaim(specPath, keyPath, outPath string, addFlag bool, regDir string) error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	var spec claimSpec
	// UseNumber so a numeric object value keeps its EXACT literal (a json.Number) instead of being
	// truncated through float64 before signing - otherwise `nekton claim` would sign 9007199254740992
	// when the author typed ...993, and CanonValue (which now rejects an imprecise integer) never sees
	// the real value. With json.Number the big int survives to canonicalization and is REJECTED, so the
	// signer is told rather than silently signing a different number (cold-session sibling-path finding).
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&spec); err != nil {
		return err
	}
	priv, err := loadPriv(keyPath)
	if err != nil {
		return err
	}
	return signClaim(spec, priv, outPath, addFlag, regDir)
}

// buildClaimEnv canonicalizes a claimSpec into a signed in-toto Statement (SPEC §7.3) and returns the
// envelope JSON bytes plus the claim id. The one signing path, shared by the file and --add forms.
func buildClaimEnv(spec claimSpec, priv ed25519.PrivateKey) ([]byte, string, error) {
	body, err := spec.buildPredicate()
	if err != nil {
		return nil, "", err
	}
	pt := spec.PredicateType
	if pt == "" {
		pt = claim.PredicateType
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjectsOf(spec.Subject),
		"predicateType": pt,
		"predicate":     body,
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		return nil, "", err
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := map[string]any{
		"payloadType": core.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]any{
			"keyid": keyidHex(priv.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return out, claim.ClaimID(payload), nil
}

// signClaim builds the claim, writes the envelope to outPath (unless --add was given without an
// explicit -o), and optionally ingests it into a registry. Shared by `nekton claim` and `nekton
// annotate`.
func signClaim(spec claimSpec, priv ed25519.PrivateKey, outPath string, addFlag bool, regDir string) error {
	b, id, err := buildClaimEnv(spec, priv)
	if err != nil {
		return err
	}
	writeFile := outPath != "" || !addFlag
	if outPath == "" {
		outPath = "claim.dsse.json"
	}
	if writeFile {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			return err
		}
	}
	dest := "-> " + outPath
	if !writeFile {
		dest = "(no -o file written; ingested via --add below)"
	}
	fmt.Printf("claim %s  keyid=%s  %s\n", id, keyidHex(priv.Public().(ed25519.PublicKey)), dest)
	if addFlag {
		var env core.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			return err
		}
		r, err := registry.Open(regOrDefault(regDir))
		if err != nil {
			return err
		}
		rid, isNew, err := r.Add(env)
		if err != nil {
			return err
		}
		if isNew {
			fmt.Printf("indexed claim %s  (registry now holds %d claims)\n", rid, r.Len())
		} else {
			fmt.Printf("already present: claim %s\n", rid)
		}
	}
	return nil
}
