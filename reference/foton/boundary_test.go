package foton_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
)

func hex64(b string) string { return "sha256:" + strings.Repeat(b, 32) }

// AUD-09. FotonID took the supplied hash strings verbatim while the signing path normalized them on
// the way through the in-toto subject, so an ACCEPTED uppercase hash gave the helper and the signed
// record different ids for the same spec. A cockpit that precomputes a result id then held a
// reference that did not resolve to the record it went on to sign - and that helper is part of the
// public authoring API extracted for exactly such integrations.
func TestPrecomputedIDMatchesTheSignedID(t *testing.T) {
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	base := foton.Spec{
		Inputs:   []foton.FileSpec{{Path: "in", Hash: hex64("ab")}},
		Outputs:  []foton.FileSpec{{Path: "out", Hash: hex64("cd")}},
		Protocol: &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"command": "noop"}},
	}
	canonical, err := foton.FotonID(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, spelling := range map[string]string{
		"canonical lowercase": hex64("ab"),
		"uppercase hex":       strings.ToUpper(hex64("ab")),
		"bare hex, no prefix": strings.Repeat("ab", 32),
		"surrounding spaces":  "  " + hex64("ab") + "  ",
	} {
		t.Run(name, func(t *testing.T) {
			spec := base
			spec.Inputs = []foton.FileSpec{{Path: "in", Hash: spelling}}
			helper, err := foton.FotonID(spec)
			if err != nil {
				t.Fatalf("this spelling is accepted elsewhere and must not be refused here: %v", err)
			}
			_, signed, err := foton.SignWith(spec, priv)
			if err != nil {
				t.Fatal(err)
			}
			if helper != signed {
				t.Errorf("precomputed id %s != signed id %s - a reference built from the helper would\n"+
					"not resolve to the record actually signed", helper, signed)
			}
			if helper != canonical {
				t.Errorf("id %s differs from the canonical spelling's %s - one value, one identity", helper, canonical)
			}
		})
	}
}

// AUD-10. Validate checked only the predicate and the presence of a protocol. A signed foton with
// two different hashes at the same ABSOLUTE input path was accepted and indexed; computing its
// action key then failed, and the registry silently omitted the action-key index while leaving the
// record queryable everywhere else. A structural violation must be refused at the boundary, not
// turned into a missing index nobody is told about.
func TestValidateRefusesStructurallyInvalidSpecs(t *testing.T) {
	proto := &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"command": "noop"}}
	out := []foton.FileSpec{{Path: "out", Hash: hex64("cd")}}

	for name, in := range map[string][]foton.FileSpec{
		"a hash that is not a hash":       {{Path: "in", Hash: "sha256:garbage"}},
		"wrong hash length":               {{Path: "in", Hash: "sha256:abcd"}},
		"an absolute path":                {{Path: "/etc/passwd", Hash: hex64("ab")}},
		"a path escaping the work tree":   {{Path: "../outside", Hash: hex64("ab")}},
		"two inputs at one path":          {{Path: "in", Hash: hex64("ab")}, {Path: "in", Hash: hex64("cd")}},
		"the same, via a dotted spelling": {{Path: "in", Hash: hex64("ab")}, {Path: "./in", Hash: hex64("cd")}},
	} {
		t.Run(name, func(t *testing.T) {
			spec := foton.Spec{Inputs: in, Outputs: out, Protocol: proto}
			if err := spec.Validate(); err == nil {
				t.Error("accepted a structurally invalid spec")
			}
			// And nothing invalid can be authored: the id helper and the signing path both refuse.
			if _, err := foton.FotonID(spec); err == nil {
				t.Error("FotonID computed an identity for a spec that has none")
			}
			if _, _, err := foton.SignWith(spec, ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))); err == nil {
				t.Error("signed a structurally invalid foton")
			}
		})
	}

	// The legitimate shapes must survive: an UNBOUND slot is a path-only "potential" (SPEC §6.1),
	// and two inputs may share a path when they carry the SAME hash.
	for name, spec := range map[string]foton.Spec{
		"a path-only unbound input": {Inputs: []foton.FileSpec{{Path: "in"}}, Outputs: out, Protocol: proto},
		"a path-only unbound output": {Inputs: []foton.FileSpec{{Path: "in", Hash: hex64("ab")}},
			Outputs: []foton.FileSpec{{Path: "out"}}, Protocol: proto},
		"one path, one hash, twice": {Inputs: []foton.FileSpec{{Path: "in", Hash: hex64("ab")}, {Path: "in", Hash: hex64("ab")}},
			Outputs: out, Protocol: proto},
		"a nested relative path": {Inputs: []foton.FileSpec{{Path: "data/in.csv", Hash: hex64("ab")}},
			Outputs: out, Protocol: proto},
	} {
		t.Run("accepted: "+name, func(t *testing.T) {
			if err := spec.Validate(); err != nil {
				t.Errorf("refused a legitimate spec: %v", err)
			}
		})
	}
}

// AUD-08. The authoring parser decoded straight into a struct, which destroys the evidence: Go keeps
// the LAST of a duplicate name and stops at the end of the first document. A misspelled field
// vanished silently, so the signed foton was not the one described.
func TestParseSpecRefusesWhatWouldVanish(t *testing.T) {
	good := `{"inputs":[{"path":"in","hash":"` + hex64("ab") + `"}],` +
		`"outputs":[{"path":"out","hash":"` + hex64("cd") + `"}],` +
		`"protocol":{"kind":"test","descriptor":{"command":"noop"}}}`
	if _, err := foton.ParseSpec([]byte(good)); err != nil {
		t.Fatalf("the documented shape must parse: %v", err)
	}
	for name, raw := range map[string]string{
		"a duplicate known field": `{"inputs":[],"inputs":[{"path":"in","hash":"` + hex64("ab") + `"}],` +
			`"outputs":[],"protocol":{"kind":"test","descriptor":{}}}`,
		"a misspelled field": `{"inpust":[{"path":"in","hash":"` + hex64("ab") + `"}],` +
			`"outputs":[],"protocol":{"kind":"test","descriptor":{}}}`,
		"a trailing second document": good + ` {"ignored":true}`,
		"trailing junk":              good + ` garbage`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := foton.ParseSpec([]byte(raw)); err == nil {
				t.Error("accepted input whose content would be silently dropped before signing")
			}
		})
	}
	// The opaque descriptor stays fully extensible - DisallowUnknownFields constrains only struct
	// targets, and a descriptor is a map.
	t.Run("an arbitrary descriptor is carried", func(t *testing.T) {
		raw := `{"inputs":[],"outputs":[{"path":"out","hash":"` + hex64("cd") + `"}],` +
			`"protocol":{"kind":"container","descriptor":{"image":"x@sha256:...","anything":{"nested":[1,2]}}}}`
		spec, err := foton.ParseSpec([]byte(raw))
		if err != nil {
			t.Fatalf("a documented opaque descriptor must be accepted: %v", err)
		}
		if _, ok := spec.Protocol.Descriptor["anything"]; !ok {
			t.Error("the descriptor lost a member")
		}
	})
}

// AUD-10. `len(descriptor) == 0` conflated `descriptor: {}` with no descriptor at all, so an empty
// object let an arbitrary incorrect ref through unchecked and put it in the bare/unverifiable
// action-key namespace. §6.2 requires hashing any descriptor that is PRESENT; only absent is
// unverifiable.
func TestAPresentEmptyDescriptorIsStillHashed(t *testing.T) {
	wrongRef := core.HashBytes([]byte("bogus"))

	empty := core.Foton{Protocol: core.Protocol{Kind: "test", Ref: wrongRef, Descriptor: map[string]any{}}}
	if err := empty.CheckProtocolRef(); err == nil {
		t.Error("a present-but-empty descriptor let an arbitrary ref through")
	}
	right, err := core.ComputeProtocolRef(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	ok := core.Foton{Protocol: core.Protocol{Kind: "test", Ref: right, Descriptor: map[string]any{}}}
	if err := ok.CheckProtocolRef(); err != nil {
		t.Errorf("the correct ref for {} must be accepted: %v", err)
	}

	// An ABSENT descriptor is a bare reference: unverifiable, not invalid. It keeps its own
	// action-key namespace so it can never collide with a verifiable inline descriptor.
	absent := core.Foton{Protocol: core.Protocol{Kind: "test", Ref: wrongRef}}
	if err := absent.CheckProtocolRef(); err != nil {
		t.Errorf("a bare ref is unverifiable, not invalid: %v", err)
	}
	akEmpty, err := ok.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	akAbsent, err := absent.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	if akEmpty == akAbsent {
		t.Error("a verifiable empty descriptor and a bare ref must not share an action key")
	}
}
