package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// signFoton builds a genuinely signed foton whose single input carries the given hash, so two calls
// with different hashes produce two DIFFERENT fotons - different covered projections, different ids.
// uris go on the OUTPUT and are carried, not covered (§6.1), so they make a TWIN: same id, different
// payload bytes. Both shapes are needed here, and they must not be confused.
func signFoton(t *testing.T, inHash string, uris []string) (core.Envelope, string) {
	t.Helper()
	desc := map[string]any{"cmd": "cp in.csv out.csv"}
	ref, err := core.ComputeProtocolRef(desc)
	if err != nil {
		t.Fatal(err)
	}
	subj := map[string]any{"name": "out.csv", "digest": map[string]any{"sha256": strings.Repeat("c", 64)}}
	if len(uris) > 0 {
		subj["uri"] = uris
	}
	b, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": core.PredicateFoton,
		"subject":       []any{subj},
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in.csv", "digest": map[string]any{"sha256": inHash}}},
			"protocol": map[string]any{"kind": "script", "ref": ref, "descriptor": desc},
		},
	})
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
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(env.PayloadType, payload))),
	})
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	return env, id
}

// TestReIngestRepairsAPlantedObject: `persistRecord` reused whatever envelope was already at the
// object path, on the strength of it being there. An object whose stored `fotonId` named the target
// while its signed envelope described a DIFFERENT foton therefore kept its own envelope -
// unionSignatures keeps the first when the payloads differ - and:
//
//	new=true, err=nil, Len()=0, degraded 1 -> 2
//
// `Add` reported a successful repair, `apply` rejected the retained envelope again, and re-ingesting
// the authentic foton could never fix it. A store with one planted file had a record that could not
// be healed by the one operation that is supposed to heal it.
//
// The test is identity, not bytes - which is exactly what keeps the legitimate case working, so the
// second subtest is not optional garnish: a co-signed twin shares the covered projection and
// therefore the id, while its payload bytes differ. It must still merge.
func TestReIngestRepairsAPlantedObject(t *testing.T) {
	t.Run("a planted object does not survive re-ingestion of the real foton", func(t *testing.T) {
		dir := t.TempDir()
		target, targetID := signFoton(t, strings.Repeat("a", 64), nil)
		impostor, impostorID := signFoton(t, strings.Repeat("b", 64), nil)
		if targetID == impostorID {
			t.Fatal("the two fotons share an id, so nothing is being planted")
		}

		// Plant it: the impostor's envelope, filed under the TARGET's id.
		objPath := filepath.Join(dir, "objects", "sha256", strings.TrimPrefix(targetID, "sha256:")+".json")
		if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
			t.Fatal(err)
		}
		planted, err := json.MarshalIndent(map[string]any{
			"fotonId": targetID, "envelope": impostor,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(objPath, planted, 0o644); err != nil {
			t.Fatal(err)
		}

		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if r.Len() != 0 {
			t.Fatalf("the planted object was indexed (Len=%d) - the premise is gone", r.Len())
		}

		id, isNew, err := r.Add(target)
		if err != nil {
			t.Fatalf("re-ingesting the authentic foton: %v", err)
		}
		if id != targetID {
			t.Errorf("Add returned %s, want %s", id, targetID)
		}
		// The acceptance criterion: either a valid indexed record, or an explicit error. Not
		// "new=true, err=nil" over a store that still holds nothing.
		if !isNew {
			t.Error("Add reported the record as already present")
		}
		if r.Len() != 1 {
			t.Fatalf("Add reported success and the registry holds %d fotons", r.Len())
		}
		if _, ok := r.Foton(targetID); !ok {
			t.Error("the repaired record is not in the live index")
		}

		// And it survives a reopen - a repair that only exists in memory is not a repair.
		r2, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if r2.Len() != 1 {
			t.Fatalf("after reopen the registry holds %d fotons", r2.Len())
		}
		env, ok := r2.Envelope(targetID)
		if !ok || env.Payload != target.Payload {
			t.Error("the stored envelope is still not the authentic one")
		}
		if n := r2.Degraded(); n != 0 {
			t.Errorf("reopen still reports %d degraded records", n)
		}
	})

	t.Run("a genuine co-signature still merges", func(t *testing.T) {
		dir := t.TempDir()
		// The case unionSignatures is FOR: the same signed bytes, two signers. Deliberately not the
		// differing-payload twin (same id, different carried `uri`) - that one keeps a single
		// signature both before and after this change, and it is the known 0.2 limitation recorded
		// at the head of CHANGELOG, not something to assert here. Checked against `dev` rather than
		// assumed: the count is 1 there too.
		a, idA := signFoton(t, strings.Repeat("a", 64), nil)
		b, idB := resign(t, a)
		if idA != idB {
			t.Fatalf("re-signing changed the id (%s vs %s)", idA, idB)
		}
		if a.Signatures[0].KeyID == b.Signatures[0].KeyID {
			t.Fatal("both envelopes carry the same signer, so nothing is being co-signed")
		}
		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(a); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(b); err != nil {
			t.Fatal(err)
		}
		r2, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		env, ok := r2.Envelope(idA)
		if !ok {
			t.Fatal("the record vanished")
		}
		if len(env.Signatures) != 2 {
			t.Errorf("the twin kept %d signatures, want 2 - the identity check must not break co-signing",
				len(env.Signatures))
		}
	})
}

// resign produces the same payload signed by a DIFFERENT key - a genuine co-signature: identical
// bytes, identical id, a second signer. This is what unionSignatures exists to merge, and what the
// identity check in persistRecord must not break.
func resign(t *testing.T, env core.Envelope) (core.Envelope, string) {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := core.Envelope{PayloadType: env.PayloadType, Payload: env.Payload}
	out.Signatures = append(out.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		KeyID: core.KeyIDHex(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(out.PayloadType, payload))),
	})
	st, err := out.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.FotonID()
	if err != nil {
		t.Fatal(err)
	}
	return out, id
}

// TestAnUnsignedSameIDObjectDoesNotDefeatRepair: the #145 check verified an existing object's
// derived foton id and stopped there. An envelope can derive the right id and still be one this
// store would never admit - the reported case is a signature ARRAY whose single entry carries an
// empty `sig`. `HasSignature` correctly calls that unsigned, but the union's `len(m.Signatures) > 0`
// counted the entry, so the stored envelope won (payloads differ, union keeps the first) and:
//
//	Add(A): new=true err=<nil>     Len()=0 before, after, and after a reopen
//
// which is exactly the repair #145 exists to make possible, defeated. Identity was necessary and not
// sufficient; `CheckAdmissible` - the gate `Add` runs, extracted so `verify` could stop keeping a
// shorter copy of it - is the sufficient one.
func TestAnUnsignedSameIDObjectDoesNotDefeatRepair(t *testing.T) {
	dir := t.TempDir()
	target, targetID := signFoton(t, strings.Repeat("a", 64), nil)
	// Same COVERED projection, so the same id; different bytes, so the union keeps the first.
	variant, variantID := signFoton(t, strings.Repeat("a", 64), []string{"https://mirror.example/out.csv"})
	if targetID != variantID {
		t.Fatalf("the variant does not share an id (%s vs %s) - the premise is gone", targetID, variantID)
	}
	if target.Payload == variant.Payload {
		t.Fatal("identical payloads - the union would not prefer the stored one")
	}
	variant.Signatures[0].Sig = "" // present as an ARRAY ENTRY, empty as a signature

	objPath := filepath.Join(dir, "objects", "sha256", strings.TrimPrefix(targetID, "sha256:")+".json")
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(map[string]any{"fotonId": targetID, "envelope": variant}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(target); err != nil {
		t.Fatalf("re-ingesting the authentic foton: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Add reported success and the registry holds %d fotons", r.Len())
	}
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env, held := r2.Envelope(targetID)
	if !held || env.Payload != target.Payload {
		t.Error("after reopen the authentic envelope is not what is stored")
	}
	if n := r2.Degraded(); n != 0 {
		t.Errorf("reopen still reports %d degraded records", n)
	}
}
