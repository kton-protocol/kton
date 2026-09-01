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
func ParseSpec(raw []byte) (Spec, error) {
	var spec Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&spec); err != nil {
		return Spec{}, err
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
func (spec Spec) Validate() error {
	if spec.Predicate != "" && spec.Predicate != "foton" {
		return fmt.Errorf("plankton authors only fotons; %q is an attestation - use `nekton claim` (nekton layer)", spec.Predicate)
	}
	if spec.Protocol == nil {
		return fmt.Errorf("foton spec needs a protocol")
	}
	return nil
}

// StatementPayload canonicalizes a Spec into the in-toto Statement bytes that get signed (SPEC
// §6.3). These bytes are both the DSSE payload and what the signature covers. `protocol.ref` is
// DERIVED from the descriptor here, so a caller can never decouple the recorded ref from the actual
// protocol.
func StatementPayload(spec Spec) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	ref, err := core.ComputeProtocolRef(spec.Protocol.Descriptor)
	if err != nil {
		return nil, err
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
	if err := spec.Validate(); err != nil {
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
