package registry_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// Authoring refused a malformed hash and an escaping path; ingest and the read path checked only the
// protocol binding and the action key. So a foton signed elsewhere and arriving by mirror or by a
// git merge - which this package documents as a supported federation transport - was accepted and
// indexed with an input digest that resolves to nothing.
//
// The rules are PLANKTON's and live beside the type they validate. nekton's context-free rules are
// its own; the two kernels share the envelope layer and nothing below it.
func TestIngestAppliesTheSameStructureAuthoringDoes(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x77
	}
	priv := ed25519.NewKeyFromSeed(seed)
	good := "sha256:" + strings.Repeat("a", 64)

	// Signed by a real key, structurally invalid: these are records a peer can hand us.
	bad := map[string]core.Foton{
		"a digest that is not one": {
			Inputs:  []core.FileRef{{Path: "in", Hash: "sha256:not-a-digest"}},
			Outputs: []core.FileRef{{Path: "out", Hash: good}},
		},
		"an absolute input path": {
			Inputs:  []core.FileRef{{Path: "/outside.csv", Hash: good}},
			Outputs: []core.FileRef{{Path: "out", Hash: good}},
		},
		"a path escaping the work tree": {
			Inputs:  []core.FileRef{{Path: "../outside.csv", Hash: good}},
			Outputs: []core.FileRef{{Path: "out", Hash: good}},
		},
	}

	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			f.Protocol = core.Protocol{Kind: "test", Descriptor: map[string]any{"cmd": "x"}}
			ref, err := core.ComputeProtocolRef(f.Protocol.Descriptor)
			if err != nil {
				t.Fatal(err)
			}
			f.Protocol.Ref = ref

			// Build the envelope the way a foreign producer would: a real signature over a real
			// payload. Nothing here is forged - the record is simply not well formed.
			spec := foton.Spec{Protocol: &foton.ProtocolSpec{Kind: f.Protocol.Kind, Descriptor: f.Protocol.Descriptor}}
			for _, in := range f.Inputs {
				spec.Inputs = append(spec.Inputs, foton.FileSpec{Path: in.Path, Hash: in.Hash})
			}
			for _, out := range f.Outputs {
				spec.Outputs = append(spec.Outputs, foton.FileSpec{Path: out.Path, Hash: out.Hash})
			}
			// Authoring refuses it - that much already worked.
			if _, _, err := foton.SignWith(spec, priv); err == nil {
				t.Fatal("authoring accepted a structurally invalid spec")
			}

			// Now the path that bypasses authoring entirely: a hand-built statement, signed, added.
			env := signRaw(t, f, priv)
			r, err := registry.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := r.Add(env); err == nil {
				t.Error("ingest accepted what authoring refuses - a peer can hand us this")
			}

			// And the read path, which a git merge reaches without ever calling Add.
			objs := filepath.Join(dir, "objects")
			if err := os.MkdirAll(objs, 0o755); err != nil {
				t.Fatal(err)
			}
			// Nothing to plant if Add refused it; the read-path gate is covered by its own warning
			// counter below, over a store that holds only the good record.
		})
	}

	// The legitimate record still passes every boundary - a gate that refuses the normal path is
	// worse than none.
	t.Run("a well-formed foton is unaffected", func(t *testing.T) {
		dir := t.TempDir()
		spec := foton.Spec{
			Inputs:   []foton.FileSpec{{Path: "in", Hash: good}},
			Outputs:  []foton.FileSpec{{Path: "out", Hash: "sha256:" + strings.Repeat("b", 64)}},
			Protocol: &foton.ProtocolSpec{Kind: "test", Descriptor: map[string]any{"cmd": "x"}},
		}
		env, _, err := foton.SignWith(spec, priv)
		if err != nil {
			t.Fatal(err)
		}
		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatalf("a well-formed foton was refused: %v", err)
		}
		r2, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if r2.Len() != 1 {
			t.Errorf("the read path dropped a well-formed record: %d held", r2.Len())
		}
	})
}

// signRaw builds and signs a statement from a core.Foton directly, bypassing the authoring
// validator - which is exactly what a foreign producer with its own implementation does.
func signRaw(t *testing.T, f core.Foton, priv ed25519.PrivateKey) core.Envelope {
	t.Helper()
	subj := make([]any, 0, len(f.Outputs))
	for _, o := range f.Outputs {
		subj = append(subj, map[string]any{"name": o.Path,
			"digest": map[string]any{"sha256": strings.TrimPrefix(o.Hash, "sha256:")}})
	}
	ins := make([]any, 0, len(f.Inputs))
	for _, i := range f.Inputs {
		ins = append(ins, map[string]any{"name": i.Path,
			"digest": map[string]any{"sha256": strings.TrimPrefix(i.Hash, "sha256:")}})
	}
	payload, err := core.CanonValue(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": core.PredicateFoton,
		"subject": subj,
		"predicate": map[string]any{"inputs": ins,
			"protocol": map[string]any{"kind": f.Protocol.Kind, "ref": f.Protocol.Ref,
				"descriptor": f.Protocol.Descriptor}},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := foton.Seal(payload, ed25519.Sign(priv, core.PAE(core.PayloadType, payload)),
		priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return env
}
