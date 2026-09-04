package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// A FOTON id is not sha256 of the envelope payload. It is computed over the COVERED projection
// (§6.3), which excludes carried uri/id/mediaType - whereas a nekton CLAIM id IS sha256 of its
// payload. That asymmetry is invisible until it bites: a Rekor entry commits to the payload hash,
// so for a claim the binding to the record is direct and for a foton it is one hop
// (subject -> stored envelope -> payload -> sha256 -> the entry's payloadHash).
//
// Pinned here because the claim case working directly is exactly what would make someone assume
// the foton case does too.
func TestFotonIDIsNotThePayloadHash(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, env := addTestFoton(t, r)

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if strings.TrimPrefix(id, "sha256:") == hex.EncodeToString(sum[:]) {
		t.Fatal("the foton id equals sha256(payload) - if that ever becomes true, the one-hop binding " +
			"note in AttachMaterial and the anchoring code that relies on it must be revisited")
	}
}

// §8.1 in the plankton store: beside the records, never inside them; never evaluated; an unknown
// scheme carried; and - the boundary that makes any of it safe - unable to affect a record read.
func TestPlanktonMaterial(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := addTestFoton(t, r)

	if err := r.AttachMaterial(VerificationMaterial{
		Subject: id, Scheme: "invented-in-2031", MediaType: "application/octet-stream",
		Material: base64.StdEncoding.EncodeToString([]byte("opaque")),
	}); err != nil {
		t.Fatalf("an unknown scheme was rejected (§8.1 requires it be carried): %v", err)
	}
	if err := r.AttachMaterial(VerificationMaterial{
		Subject: "sha256:" + strings.Repeat("e", 64), Scheme: "rfc3161",
		Material: base64.StdEncoding.EncodeToString([]byte("x")),
	}); err == nil {
		t.Error("material was attached to a foton this registry does not hold")
	}

	// It lives beside the records, in its own file.
	if _, err := os.Stat(filepath.Join(dir, "objects", "material.jsonl")); err != nil {
		t.Errorf("material file missing: %v", err)
	}

	// A corrupt material file costs no record. This is the §8.1/§11 boundary, so it is tested with
	// a file that is broken rather than merely unknown.
	if err := os.WriteFile(filepath.Join(dir, "objects", "material.jsonl"),
		[]byte("not json\n{\"subject\":\"\"}\n{{{\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(dir)
	if err != nil {
		t.Fatalf("a corrupt material file broke the registry read: %v", err)
	}
	if _, ok := r2.Foton(id); !ok {
		t.Error("the foton stopped resolving because its material file was corrupt")
	}
	if n := len(r2.Material(id)); n != 0 {
		t.Errorf("unreadable material was indexed anyway: %d", n)
	}
}

func addTestFoton(t *testing.T, r *Registry) (string, core.Envelope) {
	t.Helper()
	desc := map[string]any{"cmd": "run"}
	dc, err := core.CanonValue(desc)
	if err != nil {
		t.Fatal(err)
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out", "digest": map[string]any{"sha256": strings.Repeat("b", 64)}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs": []any{map[string]any{"name": "in", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}}},
			// protocol.ref MUST be sha256(canon(descriptor)) (§6.2) or Add rejects the record.
			"protocol": map[string]any{"kind": "script", "ref": core.HashBytes(dc), "descriptor": desc},
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: "k", Sig: base64.StdEncoding.EncodeToString(sig)})
	id, _, err := r.Add(env)
	if err != nil {
		t.Fatal(err)
	}
	return id, env
}

// The union used to merge against this process's IN-MEMORY copy, so two processes co-signing one
// record each merged into a stale view and the second atomic rename discarded the first's signature
// (`concurrency-races`, VULNERABLE on every run until #77). Atomic rename makes each write
// indivisible; it does nothing for a read-modify-write spanning two of them.
//
// This is the unit-level half of that PoC: a SECOND registry instance - a stand-in for a second
// process, with its own in-memory state - co-signs a record the first already stored. Both
// signatures must survive.
func TestCoSignatureSurvivesASecondRegistryInstance(t *testing.T) {
	dir := t.TempDir()
	r1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, env := addTestFoton(t, r1)

	// A second instance opened BEFORE the co-signature: its in-memory view is the stale one.
	r2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	twin := env
	twin.Signatures = append(append([]struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{}, env.Signatures...), struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: "second", Sig: signAsSecond(t, env)})
	if _, _, err := r2.Add(twin); err != nil {
		t.Fatal(err)
	}

	r3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r3.Envelope(id)
	if !ok {
		t.Fatal("the record vanished")
	}
	if len(got.Signatures) != 2 {
		t.Errorf("%d signature(s) on disk, want 2 - a co-signer was dropped", len(got.Signatures))
	}
}

func signAsSecond(t *testing.T, env core.Envelope) string {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(core.PayloadType, payload)))
}
