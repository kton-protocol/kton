// Package foton is the authoring front end for a foton: the small JSON a cockpit hands in, and the
// one function that turns it into the canonical in-toto Statement bytes that get signed (SPEC §6).
//
// This logic used to live in `package main` of cmd/plankton, which meant only the CLI could author
// a foton. It moved here so that EVERY authoring path assembles the payload through the same code -
// the CLI, a cockpit, and an EXECUTOR turning a completed run into a record. plankton documents and
// never executes, so the party that actually knows what went in, what came out and under what
// protocol is always someone else; if that party cannot reach a kernel authoring path, it has to
// write a second one. Two implementations of an identity rule are two opinions about identity, and
// they disagree silently: the JSON still looks right while two systems hold one record under two
// ids and stop deduplicating in the federated union (SPEC §12).
//
// This is the same move nekton/reference/claim already made for claims (#22); fotons were the half
// left behind.
//
// Signing itself is deliberately NOT here: this package produces the bytes to sign and reassembles
// the result, so a caller holding a non-extractable browser key (WebCrypto) can sign without ever
// exposing key material to Go.
package foton

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"kton.dev/plankton/core"
)

// FileSpec is one input or output: a content hash keyed by its relative work-tree path.
type FileSpec struct {
	Path string   `json:"path"`
	Hash string   `json:"hash"`
	URI  []string `json:"uri,omitempty"` // CARRIED (SPEC §6.1): fetch location(s); excluded from the foton id
}

// ProtocolSpec is the transformation descriptor a caller supplies. `ref` is not among its fields:
// it is sha256(canon(descriptor)) and is derived here, never accepted from the wire.
type ProtocolSpec struct {
	Kind       string         `json:"kind"`
	Descriptor map[string]any `json:"descriptor"`
}

// Spec is the small JSON a cockpit hands to `plankton author`. plankton authors ONLY fotons
// (reproducible results). Attestations about results - verdicts, environment-qualification,
// reviews, votes - are signed claims in the nekton layer, not here. `predicate` is accepted only as
// "foton" (or empty) for backward compatibility.
type Spec struct {
	Predicate string        `json:"predicate"` // "" | "foton" only
	Inputs    []FileSpec    `json:"inputs"`
	Outputs   []FileSpec    `json:"outputs"`
	Protocol  *ProtocolSpec `json:"protocol"`
}

// ParseSpec decodes foton-spec JSON.
//
// UseNumber so a numeric descriptor value keeps its EXACT literal instead of being truncated
// through float64 before signing - the descriptor rides into protocol.ref and therefore into the
// foton id, so a silently rounded number would change what the record means.
// ParseSpec decodes foton-spec JSON.
//
// UseNumber so a numeric descriptor value keeps its EXACT literal instead of being truncated
// through float64 before signing.
//
// The two raw-bytes checks and DisallowUnknownFields all guard the same thing: a field that
// disappears between what an author wrote and what gets signed (AUD-08). Duplicates and trailing
// documents have to be caught on the raw bytes, because decoding keeps the last duplicate and stops
// at the end of the first document. A misspelled `inputs`/`outputs`/`protocol` used to vanish
// silently, producing a signed foton that was not the one described.
//
// The opaque `descriptor` stays fully extensible: it is a map[string]any, and DisallowUnknownFields
// constrains only STRUCT targets, so any documented descriptor content is carried unchanged.
func ParseSpec(raw []byte) (Spec, error) {
	if err := core.CheckJSONDocument(raw); err != nil {
		return Spec{}, fmt.Errorf("foton spec: %w", err)
	}
	var spec Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return Spec{}, fmt.Errorf("foton spec: %w - a field this build does not know is refused "+
			"rather than dropped, because a dropped field is signed away in silence", err)
	}
	return spec, nil
}

// BareHash strips a multihash-style "sha256:" prefix, leaving the bare hex digest that the in-toto
// subject `digest` map expects.
func BareHash(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[i+1:]
	}
	return h
}

// SubjectsOf renders file specs into the in-toto subject array form (SPEC §6.3).
func SubjectsOf(fs []FileSpec) []any {
	out := make([]any, 0, len(fs))
	for _, f := range fs {
		m := map[string]any{
			"name":   f.Path,
			"digest": map[string]any{"sha256": BareHash(f.Hash)},
		}
		if len(f.URI) > 0 {
			m["uri"] = f.URI // CARRIED (SPEC §6.1): a fetch hint; not part of the foton id
		}
		out = append(out, m)
	}
	return out
}

// Validate rejects a spec this package will not sign.
// Validate enforces the STRUCTURAL grammar a foton must satisfy before anything is signed or
// indexed (SPEC §6.1, §6.3). It used to check only the predicate and the presence of a protocol, so
// a signed foton with two different hashes at the same absolute input path was accepted AND indexed;
// its action key then failed to compute, and the registry silently omitted the action-key index
// while leaving the record queryable everywhere else (AUD-10). A structural violation must be
// refused at the boundary, not turned into a missing index nobody is told about.
func (spec Spec) Validate() error {
	if spec.Predicate != "" && spec.Predicate != "foton" {
		return fmt.Errorf("plankton authors only fotons; %q is an attestation - use `nekton claim` (nekton layer)", spec.Predicate)
	}
	if spec.Protocol == nil {
		return fmt.Errorf("foton spec needs a protocol")
	}
	if err := validateFiles("input", spec.Inputs, true); err != nil {
		return err
	}
	return validateFiles("output", spec.Outputs, false)
}

// validateFiles checks one slot list. dedupePaths is true for inputs only: the §6.3 action key is a
// {relpath -> hash} map, so two inputs at one path cannot both be in the computation's identity -
// a silent last-wins would erase an input and let a 2-input foton falsely reuse a 1-input result.
// Outputs are not in the action key, so they carry no such ambiguity.
func validateFiles(kind string, fs []FileSpec, dedupePaths bool) error {
	seen := map[string]string{}
	for i, f := range fs {
		// A BOUND slot must carry a hash this substrate can actually resolve. `sha256:garbage` used
		// to be signed and indexed.
		if f.Hash != "" {
			if _, ok := core.NormalizeContentHash(f.Hash); !ok {
				return fmt.Errorf("%s[%d] %q: %q is not a sha256 content hash (SPEC §5.1)", kind, i, f.Path, f.Hash)
			}
		}
		// A path is a location INSIDE the work tree, and it is structural: it goes into the action
		// key. An absolute path, or one that escapes upward, describes a different machine's
		// filesystem rather than a reproducible computation (SPEC §6.1).
		if f.Path != "" {
			if filepath.IsAbs(f.Path) || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, `\`) {
				return fmt.Errorf("%s[%d] path %q is absolute; a foton's paths are relative to the "+
					"work tree (SPEC §6.1)", kind, i, f.Path)
			}
			if p := filepath.ToSlash(filepath.Clean(f.Path)); p == ".." || strings.HasPrefix(p, "../") {
				return fmt.Errorf("%s[%d] path %q escapes the work tree (SPEC §6.1)", kind, i, f.Path)
			}
		}
		if !dedupePaths || f.Path == "" {
			continue
		}
		key := filepath.ToSlash(filepath.Clean(f.Path))
		if prev, dup := seen[key]; dup && prev != f.Hash {
			return fmt.Errorf("two inputs share path %q with different hashes (%s, %s) - the action "+
				"key is a {path -> hash} map and could hold only one, so an input would silently "+
				"vanish from the computation's identity (SPEC §6.3)", f.Path, prev, f.Hash)
		}
		seen[key] = f.Hash
	}
	return nil
}

// normalized returns spec with every BOUND hash in canonical form (SPEC §5.1). This is the ONE
// representation every identity is computed from.
//
// FotonID used to take the supplied hash strings verbatim while the signing path normalized them on
// the way through the in-toto subject, so an accepted UPPERCASE input hash produced two different
// ids for the same spec (AUD-09):
//
//	helper: sha256:c51f96efe9abb55724b8d9c5fd17c13b48693c915771de9f11885cf86e15bb46
//	signed: sha256:409fdf21bd0e10859bd7fb43fb3a40fd7d56a165f8aa1cff5db7f04dac47313a
//
// A cockpit or executor that precomputes a result id then holds a reference that does not resolve to
// the record it goes on to sign - and that helper is part of the public authoring API extracted for
// exactly such integrations.
func (spec Spec) normalized() (Spec, error) {
	if err := spec.Validate(); err != nil {
		return Spec{}, err
	}
	out := spec
	out.Inputs = normalizeFiles(spec.Inputs)
	out.Outputs = normalizeFiles(spec.Outputs)
	return out, nil
}

// normalizeFiles copies the slice - a caller's Spec must not be mutated by asking for its id - and
// canonicalizes every bound hash. An UNBOUND slot (no hash) is left alone: a path-only slot is a
// legitimate "potential" (SPEC §6.1), not an error.
func normalizeFiles(fs []FileSpec) []FileSpec {
	if fs == nil {
		return nil
	}
	out := make([]FileSpec, len(fs))
	copy(out, fs)
	for i := range out {
		if out[i].Hash == "" {
			continue
		}
		if norm, ok := core.NormalizeContentHash(out[i].Hash); ok {
			out[i].Hash = norm
		}
	}
	return out
}

// StatementPayload canonicalizes a Spec into the in-toto Statement bytes that get signed (SPEC
// §6.3). These bytes are both the DSSE payload and what the signature covers. `protocol.ref` is
// DERIVED from the descriptor here, so a caller can never decouple the recorded ref from the actual
// protocol.
func StatementPayload(spec Spec) ([]byte, error) {
	// The SAME normalized representation FotonID uses, so the precomputed id and the id of the
	// record actually signed cannot disagree (AUD-09).
	spec, err := spec.normalized()
	if err != nil {
		return nil, err
	}
	ref, cerr := core.ComputeProtocolRef(spec.Protocol.Descriptor)
	if cerr != nil {
		return nil, cerr
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       SubjectsOf(spec.Outputs),
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs": SubjectsOf(spec.Inputs),
			"protocol": map[string]any{
				"kind":       spec.Protocol.Kind,
				"ref":        ref,
				"descriptor": spec.Protocol.Descriptor,
			},
			// CARRIED (not in the foton id / action key): the exact spec revision this was authored
			// under, so a record is traceable to its protocol version.
			"specVersion": core.SpecVersion,
		},
	}
	return core.CanonValue(st)
}

// FotonID is the content address of the foton the spec describes (SPEC §6.3) - over the COVERED
// fields only, so it does not depend on the carried `uri` hints or on the envelope.
func FotonID(spec Spec) (string, error) {
	spec, err := spec.normalized()
	if err != nil {
		return "", err
	}
	f := core.Foton{Protocol: core.Protocol{Kind: spec.Protocol.Kind, Descriptor: spec.Protocol.Descriptor}}
	for _, in := range spec.Inputs {
		f.Inputs = append(f.Inputs, core.FileRef{Hash: in.Hash, Path: in.Path})
	}
	for _, out := range spec.Outputs {
		f.Outputs = append(f.Outputs, core.FileRef{Hash: out.Hash, Path: out.Path})
	}
	ref, err := core.ComputeProtocolRef(spec.Protocol.Descriptor)
	if err != nil {
		return "", err
	}
	f.Protocol.Ref = ref
	return f.FotonID()
}

// SigningInput returns the canonical payload and the exact bytes a signer must sign over (the DSSE
// Pre-Authentication Encoding). Split out from Seal so that a caller whose private key is
// unexportable - a WebCrypto Ed25519 key in a browser - can do the raw signature itself.
func SigningInput(spec Spec) (payload, toSign []byte, err error) {
	payload, err = StatementPayload(spec)
	if err != nil {
		return nil, nil, err
	}
	return payload, core.PAE(core.PayloadType, payload), nil
}

// Seal reassembles a signature made over SigningInput's `toSign` into a DSSE envelope, and returns
// it with the foton id. It VERIFIES the signature against pub before returning: a caller that
// mismatched key and signature learns here, not when a registry later rejects the record.
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
	id, err := idFromPayload(payload)
	if err != nil {
		return core.Envelope{}, "", err
	}
	return env, id, nil
}

// idFromPayload recovers the foton id from the SIGNED bytes, so Seal reports the identity of what
// was actually signed rather than of what a caller says it signed.
func idFromPayload(payload []byte) (string, error) {
	var st core.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return "", err
	}
	f, err := st.ToFoton()
	if err != nil {
		return "", err
	}
	return f.FotonID()
}

// SignWith is the whole authoring path for a caller that HOLDS the private key (the CLI). Browser
// callers use SigningInput + Seal instead.
func SignWith(spec Spec, priv ed25519.PrivateKey) (core.Envelope, string, error) {
	payload, toSign, err := SigningInput(spec)
	if err != nil {
		return core.Envelope{}, "", err
	}
	return Seal(payload, ed25519.Sign(priv, toSign), priv.Public().(ed25519.PublicKey))
}
