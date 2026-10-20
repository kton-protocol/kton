package foton

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"kton.dev/plankton/core"
)

// The concrete environment, said by whoever ran it (SPEC §6.5, #211).
//
// A foton that declares an environment CLASS (`descriptor.environment`, a SpectrumId) is covered by
// that class: two runs of the same computation in two images of one qualified class are the same
// computation, and reuse between them is what qualifying the class is for. The exact image a producer
// ran in - an OCI digest, a nix path, a run-server id - is that producer's fact, not the record's. It
// travels here, as verification material bound to the foton id (SPEC §8.1), one signed statement per
// producer, so producers in different images of the class co-sign one foton/v1 record.
//
// Without a class nothing else says what ran, so the reference keeps the concrete environment COVERED
// there (in the descriptor), and on foton/v0, which has no place for carried material.
//
// The kernel stores and federates the material and does not read it.

// EnvScheme is the §8.1 scheme token for concrete-environment material.
const EnvScheme = "kton-env/v1"

// EnvMediaType is how the material is read: a DSSE envelope, JSON.
const EnvMediaType = "application/vnd.dsse.envelope.v1+json"

// PredicateEnv is the predicateType of the statement inside the envelope.
const PredicateEnv = "https://kton.dev/env/v1"

// EnvStatement builds the canonical statement: one subject, the foton itself (name = foton id,
// digest = its hash), and predicate {foton, envRef}.
func EnvStatement(fotonID, envRef string) ([]byte, error) {
	id, ok := core.NormalizeContentHash(fotonID)
	if !ok {
		return nil, fmt.Errorf("env material binds to a foton id, got %q", fotonID)
	}
	if strings.TrimSpace(envRef) == "" {
		return nil, fmt.Errorf("env material needs an envRef")
	}
	return core.CanonValue(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": id, "digest": map[string]any{"sha256": strings.TrimPrefix(id, "sha256:")}}},
		"predicateType": PredicateEnv,
		"predicate":     map[string]any{"foton": id, "envRef": envRef},
	})
}

// SignEnv signs a concrete-environment statement for fotonID and returns it as material, in the
// shape registry.AttachMaterial takes.
func SignEnv(fotonID, envRef string, priv ed25519.PrivateKey) (LocatorMaterial, error) {
	payload, err := EnvStatement(fotonID, envRef)
	if err != nil {
		return LocatorMaterial{}, err
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(sig)})
	raw, err := json.Marshal(env)
	if err != nil {
		return LocatorMaterial{}, err
	}
	id, _ := core.NormalizeContentHash(fotonID)
	return LocatorMaterial{Subject: id, Scheme: EnvScheme, MediaType: EnvMediaType,
		Material: base64.StdEncoding.EncodeToString(raw)}, nil
}

// RanIn is one verified concrete environment: what a producer says it ran this foton in.
type RanIn struct {
	EnvRef string `json:"envRef"`
	Signer string `json:"signer"` // keyid of the key that verified
}

// ReadEnv reads concrete-environment material about a record against a set of keys. It returns only
// what a key in keys signed, only when that same key also signed the record (the envRef is a
// producer's account of ITS OWN run), and only about that record. Material of another scheme is not an
// error - it is simply not env material (nil, nil).
//
// It refuses env material on a record that declares no environment class or is not foton/v1: there
// the concrete environment is covered, in the record itself, and a second, carried account of it would
// contradict the signed one (SPEC §6.5).
//
// Reuse across environments is sound only when the envRef is qualified for the record's class by a
// `qualifies-as` claim under a key the consumer trusts (SPEC §6.5); a class nobody qualified is only a
// label.
func ReadEnv(scheme, material string, record core.Envelope, keys []ed25519.PublicKey) (*RanIn, error) {
	if scheme != EnvScheme {
		return nil, nil
	}
	rst, err := record.Statement()
	if err != nil {
		return nil, err
	}
	f, err := rst.ToFoton()
	if err != nil {
		return nil, err
	}
	class, _ := f.Protocol.Descriptor["environment"].(string)
	if _, ok := core.NormalizeContentHash(class); f.Statement != "v1" || !ok {
		return nil, fmt.Errorf("env material on a record that is not foton/v1 with an environment class; " +
			"its concrete environment is covered in the record, and readers MUST ignore a carried one (SPEC §6.5)")
	}
	raw, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		return nil, fmt.Errorf("env material: %w", err)
	}
	var env core.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("env material: %w", err)
	}
	var signer ed25519.PublicKey
	for _, k := range keys {
		if ok, err := env.Verify(k); ok && err == nil {
			if ok, err := record.Verify(k); ok && err == nil {
				signer = k
				break
			}
		}
	}
	if signer == nil {
		return nil, fmt.Errorf("env material is not signed by a given key that also signed the record")
	}
	st, err := env.Statement()
	if err != nil {
		return nil, err
	}
	if st.Type != "https://in-toto.io/Statement/v1" || st.PredicateType != PredicateEnv {
		return nil, fmt.Errorf("env material holds a %s / %s statement", st.Type, st.PredicateType)
	}
	var p struct {
		Foton  string `json:"foton"`
		EnvRef string `json:"envRef"`
	}
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, err
	}
	id, err := f.FotonID()
	if err != nil {
		return nil, err
	}
	if p.Foton != id || len(st.Subject) != 1 || st.Subject[0].Name != id ||
		"sha256:"+st.Subject[0].Digest["sha256"] != id {
		return nil, fmt.Errorf("env material is not about %s", id)
	}
	if strings.TrimSpace(p.EnvRef) == "" {
		return nil, fmt.Errorf("env material names no envRef")
	}
	return &RanIn{EnvRef: p.EnvRef, Signer: core.KeyIDHex(signer)}, nil
}
