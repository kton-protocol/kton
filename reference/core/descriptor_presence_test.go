package core_test

import (
	"testing"

	"kton.dev/plankton/core"
)

// Identity and the action key must agree about whether a descriptor is PRESENT.
//
// FotonID marshalled Protocol through `descriptor,omitempty`, and for a map omitempty drops an EMPTY
// map as well as a nil one - so `descriptor: {}` and no descriptor at all produced the same covered
// bytes and the same foton id. EffectiveRef and ActionKey draw the opposite distinction, and
// deliberately: a bare ref is an unverifiable pointer to an off-record protocol and must not share an
// action key with an inline descriptor.
//
// Identical id, different action key: the `{}` form was taken for a duplicate of the descriptor-less
// one on ingest and never acquired its own entry in the reuse index. One record, two answers.
func TestDescriptorPresenceIsConsistentAcrossIdentityAndActionKey(t *testing.T) {
	inputs := []core.FileRef{{Path: "in", Hash: "sha256:" + rep('a')}}
	outputs := []core.FileRef{{Path: "out", Hash: "sha256:" + rep('b')}}

	emptyRef, err := core.ComputeProtocolRef(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	// Same kind, same ref, same files. The ONLY difference is that one carries `descriptor: {}` and
	// the other carries no descriptor - which is exactly the distinction the action key draws.
	present := core.Foton{Inputs: inputs, Outputs: outputs,
		Protocol: core.Protocol{Kind: "test", Ref: emptyRef, Descriptor: map[string]any{}}}
	absent := core.Foton{Inputs: inputs, Outputs: outputs,
		Protocol: core.Protocol{Kind: "test", Ref: emptyRef}}

	idP, err := present.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	idA, err := absent.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	akP, err := present.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	akA, err := absent.ActionKey()
	if err != nil {
		t.Fatal(err)
	}

	if akP == akA {
		t.Fatal("the action key no longer separates a carried descriptor from a bare ref - that " +
			"namespace is what stops a descriptor-less foton claiming a verifiable protocol's key")
	}
	if idP == idA {
		t.Errorf("`descriptor: {}` and no descriptor share the foton id %s while their action keys "+
			"differ (%s vs %s): ingest takes the second for a duplicate of the first, so it never "+
			"gets its own reuse entry", idP, akP[:23], akA[:23])
	}

	// A NON-empty descriptor and a nil one must be unaffected: their covered bytes did not change,
	// so no existing foton id moves.
	full := core.Foton{Inputs: inputs, Outputs: outputs,
		Protocol: core.Protocol{Kind: "test", Descriptor: map[string]any{"cmd": "run"}}}
	ref, err := core.ComputeProtocolRef(map[string]any{"cmd": "run"})
	if err != nil {
		t.Fatal(err)
	}
	full.Protocol.Ref = ref
	idF, err := full.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{idP, idA} {
		if idF == other {
			t.Error("a real descriptor collided with an empty or absent one")
		}
	}
}

func rep(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
