package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	nclaim "kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
	"kton.dev/plankton/core"
	preg "kton.dev/plankton/registry"
)

// variant builds a genuinely signed foton whose OUTPUT carries the given uri hints. `uri` is
// CARRIED, not covered (SPEC §6.1), so every variant here has the SAME foton id and DIFFERENT
// payload bytes - which is the whole situation this test is about.
func variant(t *testing.T, uris []string) core.Envelope {
	t.Helper()
	desc := map[string]any{"cmd": "cp in.csv out.csv"}
	ref, err := core.ComputeProtocolRef(desc)
	if err != nil {
		t.Fatal(err)
	}
	subj := map[string]any{
		"name": "out.csv", "digest": map[string]any{"sha256": strings.Repeat("c", 64)},
	}
	if len(uris) > 0 {
		subj["uri"] = uris
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": core.PredicateFoton,
		"subject":       []any{subj},
		"predicate": map[string]any{
			"inputs": []any{map[string]any{
				"name": "in.csv", "digest": map[string]any{"sha256": strings.Repeat("a", 64)},
			}},
			"protocol": map[string]any{"kind": "script", "ref": ref, "descriptor": desc},
		},
	}
	b, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := core.CanonJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := core.Envelope{
		PayloadType: core.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
	}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(env.PayloadType, payload))),
	})
	return env
}

// TestStoreAnchorKeepsWhatTheProofNeeds: `--store` reported archival success for a proof that could
// never be verified again.
//
// A foton id is the COVERED projection, and a Rekor entry binds the PAYLOAD BYTES it was handed.
// Two valid signed fotons differing only in an output `uri` therefore share an id and carry
// different bytes. Storing variant A and anchoring variant B attached the proof by id and printed
// "stored"; on reopen the only envelope present is A, and `Entry.VerifyBinds` rejects it as a
// different payload. The archived entry holds a payload digest for bytes nobody kept.
//
// The store keeps one envelope per id and `anchor` cannot add a second, so the honest outcome is a
// refusal. This test pins both halves: the mismatch is refused, and the matching case still stores.
func TestStoreAnchorKeepsWhatTheProofNeeds(t *testing.T) {
	a := variant(t, nil)
	b := variant(t, []string{"https://mirror.example/out.csv"})

	// The premise: one id, two payloads. If this ever stops holding, the rest proves nothing.
	sa, err := a.Statement()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Statement()
	if err != nil {
		t.Fatal(err)
	}
	fa, err := sa.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	fb, err := sb.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	ida, err := fa.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	idb, err := fb.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	if ida != idb {
		t.Fatalf("the two variants do not share an id (%s vs %s) - `uri` is supposed to be carried, "+
			"not covered (SPEC §6.1), so this test's premise is gone", ida, idb)
	}
	if a.Payload == b.Payload {
		t.Fatal("the two variants have identical payloads, so there is nothing to mix up")
	}

	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", dir)
	r, err := preg.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(a); err != nil {
		t.Fatalf("storing variant A: %v", err)
	}

	raw := []byte(`{"logIndex":1}`)

	t.Run("anchoring the variant the store does not hold is refused", func(t *testing.T) {
		err := storeAnchor(b, nil, raw)
		if err == nil {
			t.Fatal("stored a proof bound to bytes this store does not hold")
		}
		if !strings.Contains(err.Error(), "share an id but not their bytes") {
			t.Errorf("the refusal does not explain the collision: %v", err)
		}
		// And it really stored nothing - a refusal that half-wrote would be worse than the bug.
		rr, oerr := preg.Open(dir)
		if oerr != nil {
			t.Fatal(oerr)
		}
		if m := rr.Material(ida); len(m) != 0 {
			t.Errorf("material was attached anyway: %d entries", len(m))
		}
	})

	t.Run("anchoring the variant the store holds still works", func(t *testing.T) {
		if err := storeAnchor(a, nil, raw); err != nil {
			t.Fatalf("refused the matching variant - the gate is refusing the normal path: %v", err)
		}
		rr, oerr := preg.Open(dir)
		if oerr != nil {
			t.Fatal(oerr)
		}
		m := rr.Material(ida)
		if len(m) != 1 || m[0].Scheme != "rekor-entry" {
			t.Fatalf("material after reopen: %#v", m)
		}
		// The point of storing it: after a restart the proof still has its payload to bind against.
		env, held := rr.Envelope(ida)
		if !held || env.Payload != a.Payload {
			t.Error("the envelope the proof binds to did not survive the reopen")
		}
	})

	t.Run("a foton the store does not hold at all is refused", func(t *testing.T) {
		t.Setenv("PLANKTON_DIR", t.TempDir())
		if err := storeAnchor(a, nil, raw); err == nil {
			t.Fatal("stored a proof against a record that is not there")
		}
	})
}

// TestStoreAnchorRoutesADeferredClaim: `storeAnchor` asks the nekton registry whether it holds the
// claim, and `Claim` answers from the INDEX. A deferred claim - persisted, offered to peers, kept
// out of every index because its prev/seed has not arrived - is not there, so a claim the store
// genuinely holds fell through to the plankton branch and failed while being read as a foton:
//
//	json: cannot unmarshal string into Go struct field Subject.subject.uri of type []string
//
// A reader was told their record is malformed. It is a perfectly good claim whose predecessor has
// not turned up.
func TestStoreAnchorRoutesADeferredClaim(t *testing.T) {
	dir := t.TempDir()
	ndir := filepath.Join(dir, "nekton")
	t.Setenv("NEKTON_DIR", ndir)
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "plankton"))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, seedID, err := nclaim.SignWith(nclaim.Spec{
		Subject:       []nclaim.SubjectSpec{{URI: "urn:nekton:scope:sc"}},
		PredicateType: nclaim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "sc", "genesis": true, "by": "CN=t", "when": "2026-07-16T00:00:00Z"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	scoped, scopedID, err := nclaim.SignWith(nclaim.Spec{
		Subject: []nclaim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z",
		Scope: seedID, Prev: seedID,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nreg.Open(ndir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(scoped); err != nil {
		t.Fatal(err)
	}
	// The premise: held, and not in the index.
	if _, indexed := r.Claim(scopedID); indexed {
		t.Fatal("the claim resolved, so it is not deferred and this test proves nothing")
	}
	if _, _, ok := r.DeferredClaim(scopedID); !ok {
		t.Fatal("the claim is not deferred either - the premise is gone")
	}

	if err := storeAnchor(scoped, nil, []byte(`{"logIndex":1}`)); err != nil {
		t.Fatalf("anchoring a deferred claim failed: %v", err)
	}
	r2, err := nreg.Open(ndir)
	if err != nil {
		t.Fatal(err)
	}
	m := r2.Material(scopedID)
	if len(m) != 1 || m[0].Scheme != "rekor-entry" {
		t.Fatalf("material after reopen: %#v", m)
	}
	// A claim id IS the payload hash, so the bytes the proof binds to are preserved by the id.
	rec, _, ok := r2.DeferredClaim(scopedID)
	if !ok || rec.Envelope.Payload != scoped.Payload {
		t.Error("the envelope the proof binds to did not survive")
	}
}

// TestClaimAnchorChecksBytesToo: the claim branch skipped the byte check the foton branch makes, on
// the reasoning - written into the code - that "a claim id IS the payload hash, so the binding is
// preserved by the id itself". That is wrong, and wrong in the direction that matters: a claim id is
// sha256(canon(Statement)), the CANONICAL hash. Two genuinely signed envelopes carrying the same
// Statement in different serializations share an id and differ in bytes, and a Rekor entry binds the
// bytes it was handed.
//
//	compact   236 bytes   id sha256:59c04199…
//	indented  327 bytes   id sha256:59c04199…    both admissible
//
// So anchoring one against a store holding the other archived a proof that VerifyBinds later rejects
// as being about a different record - the exact failure the foton branch guards against, reached
// through the door that comment held open. It is the known 0.2 signature-loss limitation wearing a
// different hat.
func TestClaimAnchorChecksBytesToo(t *testing.T) {
	dir := t.TempDir()
	ndir := filepath.Join(dir, "nekton")
	t.Setenv("NEKTON_DIR", ndir)
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "plankton"))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compactEnv, id, err := nclaim.SignWith(nclaim.Spec{
		Subject: []nclaim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/note",
		Object: map[string]any{"a": "1"}, By: "CN=t", When: "2026-07-16T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := base64.StdEncoding.DecodeString(compactEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		t.Fatal(err)
	}
	pb := pretty.Bytes()
	indented := core.Envelope{PayloadType: compactEnv.PayloadType,
		Payload: base64.StdEncoding.EncodeToString(pb)}
	indented.Signatures = append(indented.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(indented.PayloadType, pb))),
	})

	// The premise, asserted rather than assumed.
	if nclaim.ClaimID(pb) != id {
		t.Fatalf("the two serializations do not share an id - the premise is gone")
	}
	if indented.Payload == compactEnv.Payload {
		t.Fatal("the two serializations have identical bytes - nothing to mix up")
	}

	r, err := nreg.Open(ndir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(compactEnv); err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"logIndex":1}`)
	if err := storeAnchor(indented, nil, raw); err == nil {
		t.Error("archived a proof bound to bytes this store does not hold")
	} else if !strings.Contains(err.Error(), "same id but not the same bytes") {
		t.Errorf("the refusal does not explain the collision: %v", err)
	}
	// And nothing was written on the way out.
	r2, err := nreg.Open(ndir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r2.Material(id)); n != 0 {
		t.Errorf("material was attached anyway: %d entries", n)
	}
	// The variant the store DOES hold still anchors.
	if err := storeAnchor(compactEnv, nil, raw); err != nil {
		t.Errorf("anchoring the stored variant was refused - the gate refuses the normal path: %v", err)
	}
}
