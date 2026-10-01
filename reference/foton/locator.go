package foton

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"kton.dev/plankton/core"
)

// Locators: where the bytes of a foton's files can be fetched, said by whoever says it.
//
// In foton/v0 a locator rides inside the signed record (`uri`, carried, not covered). That makes it
// one producer's statement welded into a record that is meant to be everybody's: a second producer
// of the same work pins different locations, signs different bytes, and cannot co-sign. foton/v1
// takes locators out (SPEC §6.6.1) and they travel here instead, as verification material bound to
// the foton id (SPEC §8.1): a small signed statement per producer, "these files of this foton can be
// fetched there". Several producers, several statements, one record.
//
// The kernel stores and federates the material like any other and does NOT read it (§8.1). This
// file is the authoring and reading side for whoever does: a cockpit, a viewer, an executor.

// LocatorScheme is the §8.1 scheme token for locator material.
const LocatorScheme = "kton-locator/v1"

// LocatorMediaType is how the material is read: a DSSE envelope, JSON.
const LocatorMediaType = "application/vnd.dsse.envelope.v1+json"

// PredicateLocator is the predicateType of the statement inside the envelope.
const PredicateLocator = "https://kton.dev/locator/v1"

// LocatorStatement builds the canonical statement: one subject per located file (name = path,
// digest, uri), ordered by path; predicate.foton names the record the files belong to. Files with
// no uri are left out - a locator statement says where bytes are, not that they exist.
func LocatorStatement(fotonID string, files []FileSpec) ([]byte, error) {
	if _, ok := core.NormalizeContentHash(fotonID); !ok {
		return nil, fmt.Errorf("locators bind to a foton id, got %q", fotonID)
	}
	var located []FileSpec
	for _, f := range normalizeFiles(files) {
		if len(f.URI) == 0 {
			continue
		}
		if f.Hash == "" {
			return nil, fmt.Errorf("%s: a locator needs the hash the fetched bytes must match", f.Path)
		}
		uris := append([]string{}, f.URI...)
		sort.Strings(uris)
		located = append(located, FileSpec{Path: f.Path, Hash: f.Hash, URI: uris})
	}
	if len(located) == 0 {
		return nil, fmt.Errorf("no file carries a uri; there is nothing to locate")
	}
	sort.SliceStable(located, func(i, j int) bool {
		if located[i].Path != located[j].Path {
			return located[i].Path < located[j].Path
		}
		return located[i].Hash < located[j].Hash
	})
	return core.CanonValue(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       SubjectsOf(located),
		"predicateType": PredicateLocator,
		"predicate":     map[string]any{"foton": fotonID},
	})
}

// LocatorMaterial is the §8.1 material ready to attach (registry.AttachMaterial takes these fields).
type LocatorMaterial struct {
	Subject   string `json:"subject"`
	Scheme    string `json:"scheme"`
	MediaType string `json:"mediaType"`
	Material  string `json:"material"`
}

// SignLocators signs a locator statement for fotonID and returns it as material.
func SignLocators(fotonID string, files []FileSpec, priv ed25519.PrivateKey) (LocatorMaterial, error) {
	payload, err := LocatorStatement(fotonID, files)
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
	return LocatorMaterial{Subject: fotonID, Scheme: LocatorScheme, MediaType: LocatorMediaType,
		Material: base64.StdEncoding.EncodeToString(raw)}, nil
}

// Located is one verified locator: the file and where it can be fetched, and who said so.
type Located struct {
	Path   string   `json:"path"`
	Hash   string   `json:"hash"`
	URI    []string `json:"uri"`
	Signer string   `json:"signer"` // keyid of the key that verified
}

// ReadLocators reads locator material about foton f against a set of keys. It returns only what a
// key in keys signed, and only files that ARE inputs or outputs of f at that path with that hash: a
// locator naming bytes the record does not contain says nothing about this record. Material of
// another scheme is not an error - it is simply not a locator (nil, nil).
func ReadLocators(scheme, material string, f core.Foton, keys []ed25519.PublicKey) ([]Located, error) {
	if scheme != LocatorScheme {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		return nil, fmt.Errorf("locator material: %w", err)
	}
	var env core.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("locator material: %w", err)
	}
	signer := core.VerifiedSignerKeyID(env, keys)
	if signer == "" {
		return nil, fmt.Errorf("locator material is not signed by any of the given keys")
	}
	st, err := env.Statement()
	if err != nil {
		return nil, err
	}
	if st.PredicateType != PredicateLocator {
		return nil, fmt.Errorf("locator material holds a %s statement", st.PredicateType)
	}
	var p struct {
		Foton string `json:"foton"`
	}
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, err
	}
	id, err := f.FotonID()
	if err != nil {
		return nil, err
	}
	if p.Foton != id {
		return nil, fmt.Errorf("locator material is about %s, not %s", p.Foton, id)
	}
	in := map[string]bool{}
	for _, r := range append(append([]core.FileRef{}, f.Inputs...), f.Outputs...) {
		in[r.Path+"\x00"+r.Hash] = true
	}
	var out []Located
	for _, s := range st.Subject {
		h, ok := core.NormalizeContentHash("sha256:" + s.Digest["sha256"])
		if !ok || !in[s.Name+"\x00"+h] {
			return nil, fmt.Errorf("locator names %s at %s, which is not a file of this foton", s.Name, h)
		}
		out = append(out, Located{Path: s.Name, Hash: h, URI: s.URI, Signer: signer})
	}
	return out, nil
}
