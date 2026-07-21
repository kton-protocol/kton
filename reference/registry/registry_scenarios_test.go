package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// addNormalizer signs and ingests a normalizer foton (in -> out) with a bare protocol ref (the
// potential identity), so two normalizers can be given DISTINCT refs.
func addNormalizer(t *testing.T, r *registry.Registry, inHex, outHex, ref string) {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out", "digest": map[string]any{"sha256": outHex}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in", "digest": map[string]any{"sha256": inHex}}},
			"protocol": map[string]any{"kind": "normalize", "ref": ref},
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
	if _, _, err := r.Add(env); err != nil {
		t.Fatalf("add normalizer: %v", err)
	}
}

// TestNormalizedOutputMatchesPotentialNotKind: L1 must match on the normalizer POTENTIAL (its ref),
// not merely its kind. Two DIFFERENT normalizers (distinct refs, same kind) that both converge to a
// common output must NOT both satisfy one L1 assertion (SPEC §9; cold-session over-claim).
func TestNormalizedOutputMatchesPotentialNotKind(t *testing.T) {
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rawA := strings.Repeat("a1", 32)
	rawB := strings.Repeat("b2", 32)
	common := strings.Repeat("cc", 32)
	refA := "sha256:" + strings.Repeat("11", 32)
	refB := "sha256:" + strings.Repeat("22", 32)
	addNormalizer(t, r, rawA, common, refA) // potential A normalizes rawA -> common
	addNormalizer(t, r, rawB, common, refB) // DIFFERENT potential B normalizes rawB -> common

	if got := r.NormalizedOutput("sha256:"+rawA, refA); got != "sha256:"+common {
		t.Fatalf("potential A should normalize rawA to common, got %q", got)
	}
	// rawB was normalized by potential B, so via potential A it must NOT resolve - no cross-potential L1
	if got := r.NormalizedOutput("sha256:"+rawB, refA); got != "" {
		t.Fatalf("rawB (normalized by a different potential) must not match refA, got %q", got)
	}
}

// authorFoton builds and signs a minimal foton envelope (input tree -> protocol -> output tree).
func authorFoton(t *testing.T, inHex, outHex string) core.Envelope {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out.csv", "digest": map[string]any{"sha256": outHex}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in.csv", "digest": map[string]any{"sha256": inHex}}},
			"protocol": map[string]any{"kind": "script", "ref": "sha256:proto"},
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
	return env
}

// TestAddRejectsUnsignedAndRefMismatch: ingest admits only SIGNED records (SPEC §8) and rejects a
// foton whose protocol.ref does not hash to its descriptor (SPEC §6.2). Both are cold-session fixes:
// plankton used to admit unsigned fotons, and a forged ref used to poison the reuse cache.
func TestAddRejectsUnsignedAndRefMismatch(t *testing.T) {
	const (
		in  = "1111111111111111111111111111111111111111111111111111111111111111"
		out = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// (a) an unsigned foton is rejected - both a nil signatures array and a present-but-substanceless
	// entry (a signature with an empty sig is not a signature).
	env := authorFoton(t, in, out)
	env.Signatures = nil
	if _, _, err := r.Add(env); err == nil {
		t.Fatal("Add must reject an unsigned foton (SPEC §8)")
	}
	empty := authorFoton(t, in, out)
	empty.Signatures[0].Sig = "" // keyid present, no signature bytes
	if _, _, err := r.Add(empty); err == nil {
		t.Fatal("Add must reject a foton whose only signature has empty sig bytes (SPEC §8)")
	}

	// (b) a foton carrying a descriptor whose ref does not match sha256(canon(descriptor)) is rejected
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out.csv", "digest": map[string]any{"sha256": out}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in.csv", "digest": map[string]any{"sha256": in}}},
			"protocol": map[string]any{"kind": "script", "ref": "sha256:" + in, "descriptor": map[string]any{"cmd": "run"}},
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	bad := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	bad.Signatures = append(bad.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: "k", Sig: base64.StdEncoding.EncodeToString(sig)})
	if _, _, err := r.Add(bad); err == nil {
		t.Fatal("Add must reject a foton whose protocol.ref does not match its descriptor (SPEC §6.2)")
	}
}

// TestHashBindingAndIncompleteLineage converts spec-test Scenario 2 (the Forger) and Scenario 9
// (the Orphan):
//   - a foton's id is DERIVED from its content (the registry recomputes it; a producer cannot assert
//     a false id) - so a reference by hash cannot point to different content;
//   - a foton whose input has no visible producer is a lineage ROOT: its lineage is INCOMPLETE, not
//     invalid - the foton itself remains present and verifiable.
func TestHashBindingAndIncompleteLineage(t *testing.T) {
	const (
		in   = "1111111111111111111111111111111111111111111111111111111111111111"
		out  = "2222222222222222222222222222222222222222222222222222222222222222"
		out2 = "3333333333333333333333333333333333333333333333333333333333333333"
	)
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Scenario 2: Add derives the id from the envelope's content, independent of any assertion.
	env := authorFoton(t, in, out)
	id, isNew, err := r.Add(env)
	if err != nil || !isNew {
		t.Fatalf("add: %v isNew=%v", err, isNew)
	}
	st, _ := env.Statement()
	f, _ := st.ToFoton()
	if want, _ := f.FotonID(); id != want {
		t.Fatalf("id must be the content hash of the foton: %s != %s", id, want)
	}
	// Different content (different output) must not share an id - hash binding.
	id2, _, err := r.Add(authorFoton(t, in, out2))
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id {
		t.Fatal("different content must not share an id (hash binding)")
	}

	// producer resolution: the output resolves to its foton; a wrong hash resolves to nothing.
	if p := r.Producer("sha256:" + out); len(p) != 1 || p[0] != id {
		t.Fatalf("producer of output should be the foton, got %v", p)
	}
	if p := r.Producer("sha256:deadbeef"); len(p) != 0 {
		t.Fatalf("an unknown hash must have no producer, got %v", p)
	}

	// Scenario 9: the input has no producer -> a lineage ROOT (incomplete), yet the foton is valid+present.
	if p := r.Producer("sha256:" + in); len(p) != 0 {
		t.Fatalf("input has no producer (a lineage root / incomplete), got %v", p)
	}
	if _, ok := r.Foton(id); !ok {
		t.Fatal("the foton must remain present/valid despite incomplete lineage")
	}
	if u := r.Uses("sha256:" + in); len(u) != 2 {
		t.Fatalf("both fotons consume the input, got %d", len(u))
	}
}

// TestOpenUnionJoinsAcrossSources: two SEPARATE registries (B builds on A's output but never mirrors
// it) join at the shared hash only when both are named as sources. Over B alone the lineage is
// incomplete (not invalid); the union resolves it. Naming a source twice must not double-count.
func TestOpenUnionJoinsAcrossSources(t *testing.T) {
	raw := strings.Repeat("a", 64)
	mid := strings.Repeat("b", 64)
	out := strings.Repeat("c", 64)
	dirA, dirB := t.TempDir(), t.TempDir()

	rA, err := registry.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rA.Add(authorFoton(t, raw, mid)); err != nil { // A: raw -> mid
		t.Fatal(err)
	}
	rB, err := registry.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rB.Add(authorFoton(t, mid, out)); err != nil { // B: mid -> out
		t.Fatal(err)
	}

	if got := len(rB.Lineage("sha256:" + out)); got != 1 {
		t.Fatalf("B alone: want 1 foton (incomplete), got %d", got)
	}
	u, err := registry.OpenUnion(dirA, dirB)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(u.Lineage("sha256:" + out)); got != 2 {
		t.Fatalf("union A+B: want 2 fotons joined across sources, got %d", got)
	}
	u2, err := registry.OpenUnion(dirA, dirA, dirB)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(u2.Lineage("sha256:" + out)); got != 2 {
		t.Fatalf("dedup: naming A twice must not double-count, got %d", got)
	}
}

// TestStrictIgnoresForeignFilesButCountsUnsigned covers strict-bypass F2/F3: a foreign *.json under
// objects/ (not a <algo>/<hex>.json record path) must NOT count as a degraded/skipped record (else a
// stray file false-alarms --strict), while a record planted directly on disk WITHOUT a well-formed
// signature IS counted by Unsigned() so --strict can refuse over it (the read path skips the ingest
// signature gate that Add enforces).
func TestStrictIgnoresForeignFilesButCountsUnsigned(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	addNormalizer(t, r, strings.Repeat("a1", 32), strings.Repeat("cc", 32), "sha256:"+strings.Repeat("11", 32))

	objSha := filepath.Join(dir, "objects", "sha256")
	// a foreign file whose NAME is not a content hash, and a stray file one level up: neither is a record
	if err := os.WriteFile(filepath.Join(objSha, "README.json"), []byte(`{"note":"not a record"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "objects", "notes.json"), []byte(`{garbage`), 0o644); err != nil {
		t.Fatal(err)
	}
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := r2.Degraded(); n != 0 {
		t.Errorf("F2: foreign non-record files must not count as degraded, got %d", n)
	}
	if n := r2.Unsigned(); n != 0 {
		t.Errorf("F3: the only real record is signed, want 0 unsigned, got %d", n)
	}

	// Plant a record-shaped file (hex name) carrying no well-formed signature.
	unsigned := `{"claimId":"","envelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"","sig":""}]}}`
	if err := os.WriteFile(filepath.Join(objSha, strings.Repeat("f", 64)+".json"), []byte(unsigned), 0o644); err != nil {
		t.Fatal(err)
	}
	r3, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := r3.Unsigned(); n == 0 {
		t.Errorf("F3: a planted unsigned record must be counted by Unsigned(), got 0")
	}
}
