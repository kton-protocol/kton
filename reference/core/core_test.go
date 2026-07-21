package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readEnv(t *testing.T, path string) Envelope {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func pubKey(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePublicKeyHex(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The foton DSSE envelope verifies against the author key, and NOT against the confirmer key.
func TestVectorDSSEVerify(t *testing.T) {
	env := readEnv(t, "../testdata/foton.dsse.json")
	author := pubKey(t, "../testdata/author.pub")
	confirmer := pubKey(t, "../testdata/confirmer.pub")

	if ok, err := env.Verify(author); err != nil || !ok {
		t.Fatalf("author should verify foton envelope (ok=%v err=%v)", ok, err)
	}
	if ok, _ := env.Verify(confirmer); ok {
		t.Fatal("confirmer key must NOT verify the author's envelope")
	}
}

// A signed non-foton statement (here a qualification verdict - now a nekton concern) still
// verifies through the shared DSSE layer against a DIFFERENT key than the foton's author: the
// four-eyes property. plankton itself no longer models such attestations; this exercises core
// DSSE and asserts the statement is not a foton.
func TestVectorSignedByConfirmer(t *testing.T) {
	env := readEnv(t, "../testdata/verdict.dsse.json")
	confirmer := pubKey(t, "../testdata/confirmer.pub")
	if ok, err := env.Verify(confirmer); err != nil || !ok {
		t.Fatalf("confirmer should verify the envelope (ok=%v err=%v)", ok, err)
	}
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	if st.PredicateType == PredicateFoton {
		t.Fatal("a verdict must not be a foton - attestations belong to nekton")
	}
}

// A one-byte tamper of the payload breaks verification.
func TestTamperDetected(t *testing.T) {
	env := readEnv(t, "../testdata/foton.dsse.json")
	author := pubKey(t, "../testdata/author.pub")
	b := []byte(env.Payload)
	b[10] ^= 0x01
	env.Payload = string(b)
	if ok, _ := env.Verify(author); ok {
		t.Fatal("tampered payload must not verify")
	}
}

// protocol.ref MUST equal the content address of its descriptor (spec §6.2) - checked against
// the real vector produced by the spike.
func TestProtocolRefMatchesDescriptor(t *testing.T) {
	env := readEnv(t, "../testdata/foton.dsse.json")
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ComputeProtocolRef(f.Protocol.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if got != f.Protocol.Ref {
		t.Fatalf("protocol.ref mismatch:\n stored=%s\n computed=%s\n(our canonical JSON disagrees with the spike's)", f.Protocol.Ref, got)
	}
}

// ActionKey is deterministic and stable.
func TestActionKeyDeterministic(t *testing.T) {
	env := readEnv(t, "../testdata/foton.dsse.json")
	st, _ := env.Statement()
	f, _ := st.ToFoton()
	a, err := f.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := f.ActionKey()
	if a != b || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("action key unstable or malformed: %q / %q", a, b)
	}
}

// A POTENTIAL is a foton with UNBOUND slots (FileRefs with a path and no hash): input holes
// and virtual outputs. The kernel canonicalizes them by path (no "hash" key), gives the
// potential a stable FotonID, and a realization (binding the holes + producing the outputs)
// is a distinct, bound foton. Bound FileRefs are unaffected (hash still canonicalizes).
func TestPotentialUnboundSlots(t *testing.T) {
	pot := Foton{
		Inputs:   []FileRef{{Path: "in/data.csv"}},    // an input hole (unbound)
		Outputs:  []FileRef{{Path: "out/result.csv"}}, // a virtual output (the declared mask)
		Protocol: Protocol{Kind: "normalize", Ref: "sha256:proto"},
	}
	pb, err := CanonValue(pot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pb), `"hash"`) {
		t.Fatalf("unbound slots must omit hash in canon, got: %s", pb)
	}
	potID, err := pot.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	if id2, _ := pot.FotonID(); id2 != potID {
		t.Fatal("potential FotonID must be stable")
	}

	// realize it: bind the hole + produce the declared output -> a distinct, bound foton
	real := Foton{
		Inputs:   []FileRef{{Path: "in/data.csv", Hash: "sha256:in"}},
		Outputs:  []FileRef{{Path: "out/result.csv", Hash: "sha256:out"}},
		Protocol: pot.Protocol,
	}
	realID, _ := real.FotonID()
	if realID == potID {
		t.Fatal("a realized foton must differ from its potential")
	}
	rb, _ := CanonValue(real)
	if !strings.Contains(string(rb), `"hash"`) {
		t.Fatalf("a bound foton must include hash in canon, got: %s", rb)
	}
}

// TestActionKeyBindsToDescriptor: the action key must reflect the real protocol descriptor, not an
// unverified wire ref. Two fotons with identical inputs/kind and the SAME forged ref but DIFFERENT
// descriptors are different computations and MUST get different action keys (cold-session cache-
// poisoning fix). CheckProtocolRef rejects a foton whose ref lies about its descriptor.
func TestActionKeyBindsToDescriptor(t *testing.T) {
	mk := func(cmd string) Foton {
		return Foton{
			Inputs:   []FileRef{{Path: "in.txt", Hash: "sha256:" + strings.Repeat("22", 32)}},
			Outputs:  []FileRef{{Path: "out.txt", Hash: "sha256:" + strings.Repeat("11", 32)}},
			Protocol: Protocol{Kind: "script", Ref: "sha256:" + strings.Repeat("aa", 32), Descriptor: map[string]any{"cmd": cmd}},
		}
	}
	a, b := mk("BENIGN build"), mk("MALICIOUS rm -rf /")
	ak, err := a.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	bk, err := b.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	if ak == bk {
		t.Fatalf("different descriptors sharing a forged ref must not collide on action key: %s", ak)
	}
	// a lying ref (does not hash to its descriptor) is rejected at the trust boundary
	if err := a.CheckProtocolRef(); err == nil {
		t.Fatal("CheckProtocolRef must reject a ref that does not match the descriptor")
	}
	// a well-formed foton (ref == sha256(canon(descriptor))) passes; EffectiveRef derives that ref
	want, _ := ComputeProtocolRef(a.Protocol.Descriptor)
	good := mk("BENIGN build")
	good.Protocol.Ref = want
	if err := good.CheckProtocolRef(); err != nil {
		t.Fatalf("well-formed foton must pass CheckProtocolRef: %v", err)
	}
	if eff, _ := good.Protocol.EffectiveRef(); eff != want {
		t.Fatalf("EffectiveRef must derive from descriptor: got %s want %s", eff, want)
	}
}

// TestActionKeyBareRefIsolated: a descriptor-LESS foton asserting a bare ref must NOT share an
// action key with a descriptor-FUL foton whose descriptor hashes to that same ref - the cold-session
// bypass where an attacker's bare-ref foton poisons a victim's cache. A bare ref is an unverifiable
// pointer and lives in a separate action-key namespace.
func TestActionKeyBareRefIsolated(t *testing.T) {
	desc := map[string]any{"cmd": "benign"}
	ref, _ := ComputeProtocolRef(desc)
	in := []FileRef{{Path: "in.txt", Hash: "sha256:" + strings.Repeat("22", 32)}}
	bound := Foton{Inputs: in, Protocol: Protocol{Kind: "script", Ref: ref, Descriptor: desc}}
	bare := Foton{Inputs: in, Protocol: Protocol{Kind: "script", Ref: ref}} // same ref, NO descriptor
	bk, err := bound.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := bare.ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	if bk == rk {
		t.Fatalf("a bare-ref foton must not collide with a descriptor-ful one on action key: %s", bk)
	}
}

// TestActionKeyRejectsDuplicateRelpath: two inputs at the same relpath with different hashes are an
// ambiguous computation identity and must error, not silently collapse (last-wins) into a false match.
func TestActionKeyRejectsDuplicateRelpath(t *testing.T) {
	f := Foton{
		Inputs: []FileRef{
			{Path: "data.csv", Hash: "sha256:" + strings.Repeat("11", 32)},
			{Path: "data.csv", Hash: "sha256:" + strings.Repeat("22", 32)},
		},
		Protocol: Protocol{Kind: "script", Ref: "sha256:proto"},
	}
	if _, err := f.ActionKey(); err == nil {
		t.Fatal("ActionKey must reject two inputs sharing a relpath with different hashes")
	}
}

// Environment is COVERED: an env-spectrum ref in the descriptor (SPEC §6.5) is part of
// protocol.ref and therefore the action key and foton id. Present vs absent must diverge.
func TestEnvironmentCovered(t *testing.T) {
	mk := func(env string) Foton {
		desc := map[string]any{"cmd": "run"}
		if env != "" {
			desc["environment"] = env
		}
		ref, err := ComputeProtocolRef(desc)
		if err != nil {
			t.Fatal(err)
		}
		return Foton{
			Inputs:   []FileRef{{Path: "in.csv", Hash: "sha256:aaa"}},
			Outputs:  []FileRef{{Path: "out.csv", Hash: "sha256:bbb"}},
			Protocol: Protocol{Kind: "script", Ref: ref, Descriptor: desc},
		}
	}
	bare, env := mk(""), mk("sha256:deadbeefcafe")
	ak0, _ := bare.ActionKey()
	ak1, _ := env.ActionKey()
	if ak0 == ak1 {
		t.Fatal("env-spectrum in descriptor must change the action key (covered), but they match")
	}
	id0, _ := bare.FotonID()
	id1, _ := env.FotonID()
	if id0 == id1 {
		t.Fatal("env-spectrum in descriptor must change the foton id (covered), but they match")
	}
}

// TestGoldenVectors freezes the cross-implementation contract: a second implementation MUST
// reproduce these exact values from testdata/foton.statement.json under the shipped keys
// (regenerate via testdata/gen). Any drift here is a canonicalization/identity break.
func TestGoldenVectors(t *testing.T) {
	env := readEnv(t, "../testdata/foton.dsse.json")
	st, _ := env.Statement()
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := f.FotonID()
	ak, _ := f.ActionKey()
	const wantID = "sha256:5da55d7885d87097e5decf17d7edf6e49597a655f401249cca66bd77a17121f1"
	const wantAK = "sha256:8bcde68d3d76cd4bf158c015c64aa587fb747402ce63dbdb528871488eb897fd"
	if id != wantID {
		t.Fatalf("foton id drift:\n got %s\nwant %s", id, wantID)
	}
	if ak != wantAK {
		t.Fatalf("action key drift:\n got %s\nwant %s", ak, wantAK)
	}
	if env.Signatures[0].KeyID != "b39c0a6f6af1f3e1" {
		t.Fatalf("author keyid drift: %s", env.Signatures[0].KeyID)
	}
}

// TestCarriedFieldsNotCovered - spec §6.1/§6.3: a FileRef's carried fields (id/uri/mediaType) MUST
// NOT change the foton id, but its covered fields (hash, relative path) MUST.
func TestCarriedFieldsNotCovered(t *testing.T) {
	base := Foton{
		Inputs:   []FileRef{{Hash: "sha256:in", Path: "in.csv"}},
		Outputs:  []FileRef{{Hash: "sha256:out", Path: "out.csv"}},
		Protocol: Protocol{Kind: "script", Ref: "sha256:proto"},
	}
	id, _ := base.FotonID()

	// carried fields added -> SAME id
	withCarried := base
	withCarried.Inputs = []FileRef{{Hash: "sha256:in", Path: "in.csv", URI: []string{"https://example.org/in.csv"}, ID: "hc:1", MediaType: "text/csv"}}
	if c, _ := withCarried.FotonID(); c != id {
		t.Fatalf("carried FileRef fields must not change the foton id:\n %s\n %s", id, c)
	}
	// different covered hash -> DIFFERENT id
	dh := base
	dh.Inputs = []FileRef{{Hash: "sha256:other", Path: "in.csv"}}
	if c, _ := dh.FotonID(); c == id {
		t.Fatal("a different input hash (covered) MUST change the foton id")
	}
	// different covered path -> DIFFERENT id
	dp := base
	dp.Inputs = []FileRef{{Hash: "sha256:in", Path: "other.csv"}}
	if c, _ := dp.FotonID(); c == id {
		t.Fatal("a different relative path (covered) MUST change the foton id")
	}
}
