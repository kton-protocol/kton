package claim_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// TestWireParity: the claim id is the content hash of the canonical JSON of its statement, and
// canonicalization is deterministic - the wire contract two implementations must share. (Was
// cross-checked against a spike-generated vector; that vector now lives in the research repo.)
func TestWireParity(t *testing.T) {
	st := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   "warfarin_PK ray",
			"digest": map[string]any{"sha256": "048755ecd72c2114bf80c1814824db494b555f6c30bf3547bebffc7e64b45cf1"},
		}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/confirmed"},
			"by":        "reviewer:org-pki:CN=A. Reviewer",
			"when":      "2026-06-30T16:57:06+00:00",
			"why":       "Independent review per SOP-PMX-014; results match approved criteria.",
			"evidence":  []any{map[string]any{"uri": "https://kton.dev/v/four-eyes"}},
		},
	}
	a, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := core.CanonValue(st)
	if string(a) != string(b) {
		t.Fatal("canonicalization must be deterministic")
	}
	if claim.ClaimID(a) != core.HashBytes(a) {
		t.Fatal("claim id must be the content hash of the canonical statement")
	}
}

// TestRoundTripAndIndex: author a claim over a plankton foton hash, ingest it, verify the
// signature, and resolve it by subject / predicate / signer / object (SPEC §11, §12).
func TestRoundTripAndIndex(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	subjectHash := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	objectURI := "https://kton.dev/v/valid-for-gxp"
	predURI := "https://kton.dev/v/identity-equivalent"

	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "theo_fit ray", "digest": map[string]any{"sha256": subjectHash[len("sha256:"):]}}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": predURI},
			"object":    map[string]any{"uri": objectURI},
			"by":        "qa:org-pki:CN=QA",
			"when":      "2026-07-01T00:00:00+00:00",
		},
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: "testkey000000000", Sig: base64.StdEncoding.EncodeToString(sig)})

	ok, err := env.Verify(pub)
	if err != nil || !ok {
		t.Fatalf("signature must verify: ok=%v err=%v", ok, err)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, isNew, err := r.Add(env)
	if err != nil || !isNew {
		t.Fatalf("add: id=%s isNew=%v err=%v", id, isNew, err)
	}
	if id != claim.ClaimID(payload) {
		t.Fatalf("claim id mismatch: %s", id)
	}
	// idempotent
	if _, isNew, _ := r.Add(env); isNew {
		t.Fatal("second add should be a no-op")
	}

	if got := r.About(subjectHash); len(got) != 1 {
		t.Fatalf("by-subject: want 1, got %d", len(got))
	}
	if got := r.ByPredicate(predURI); len(got) != 1 {
		t.Fatalf("by-predicate: want 1, got %d", len(got))
	}
	if got := r.BySigner("testkey000000000"); len(got) != 1 {
		t.Fatalf("by-signer: want 1, got %d", len(got))
	}
	if got := r.ByObject(objectURI); len(got) != 1 {
		t.Fatalf("by-object: want 1, got %d", len(got))
	}

	// persistence: a freshly-opened registry replays the same claim.
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.About(subjectHash)) != 1 {
		t.Fatal("claim did not survive replay")
	}
}

// signHelper signs a Statement map with a fixed key; returns the envelope + its canonical id.
func signHelper(t *testing.T, priv ed25519.PrivateKey, st map[string]any) (core.Envelope, string) {
	t.Helper()
	payload, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{KeyID: "k", Sig: base64.StdEncoding.EncodeToString(sig)})
	return env, claim.ClaimID(payload)
}

// H1: the claim id is over CANONICAL JSON, so byte-different-but-JSON-equal payloads coincide.
func TestClaimIDIsCanonical(t *testing.T) {
	a := claim.ClaimID([]byte(`{"a":1,"b":2}`))
	b := claim.ClaimID([]byte(`{"b":2,"a":1}`))
	if a != b {
		t.Fatalf("claim id must be canonical (union-by-hash): %s vs %s", a, b)
	}
}

// TestValidateRejectsNonRFC3339When (time-freshness F1): `when` is a timestamp, not free text. A
// non-RFC3339 garbage value used to sign and ingest and display as authoritative just like a real
// instant. Validate (the one ingest gate) now rejects a malformed `when`. A well-formed but
// far-future/backdated `when` is still ACCEPTED - the substrate is monotone (no supersession-aware
// read); semantic freshness/revocation is an out-of-band concern, a documented boundary, not this check.
func TestValidateRejectsNonRFC3339When(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mk := func(when string) core.Envelope {
		st := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"hash": "sha256:" + strings.Repeat("a", 64)}},
			"predicateType": claim.PredicateType,
			"predicate": map[string]any{
				"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
				"by":        "CN=a", "when": when,
			},
		}
		env, _ := signHelper(t, priv, st)
		return env
	}
	// garbage / non-RFC3339 -> REJECTED at ingest
	for _, bad := range []string{"not-a-date", "2026-13-45", "yesterday", ""} {
		r, _ := registry.Open(t.TempDir())
		if _, _, err := r.Add(mk(bad)); err == nil {
			t.Fatalf("a non-RFC3339 when %q must be rejected", bad)
		}
	}
	// well-formed instants -> ACCEPTED, INCLUDING a far-future one (the monotone boundary, documented)
	for _, ok := range []string{"2026-07-16T00:00:00Z", "2099-01-01T00:00:00Z", "2011-01-01T00:00:00+00:00"} {
		r, _ := registry.Open(t.TempDir())
		if _, _, err := r.Add(mk(ok)); err != nil {
			t.Fatalf("a well-formed RFC3339 when %q must be accepted, got %v", ok, err)
		}
	}
}

// H2: a claim/v0 statement with genesis:true must NOT be able to mint a scope.
func TestGenesisOnlyOnSeed(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "x"}},
		"predicateType": claim.PredicateType, // NOT scope/v0
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/whatever"},
			"genesis":   true, "scope": "forged", "prev": "forged",
			"by": "attacker", "when": "2026-07-01T00:00:00+00:00",
		},
	}
	env, _ := signHelper(t, priv, fake)
	r, _ := registry.Open(dir)
	if _, _, err := r.Add(env); err == nil {
		t.Fatal("genesis:true on a claim/v0 must be rejected (cannot mint a scope without scope/v0)")
	}
}

// M3: a scope/v0 seed carrying prev must be rejected.
func TestSeedMustNotCarryPrev(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "scope:x"}},
		"predicateType": claim.ScopePredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/scope"},
			"genesis":   true, "prev": "sha256:deadbeef",
			"by": "chair", "when": "2026-07-01T00:00:00+00:00",
		},
	}
	env, _ := signHelper(t, priv, seed)
	r, _ := registry.Open(dir)
	if _, _, err := r.Add(env); err == nil {
		t.Fatal("a seed carrying prev must be rejected (SPEC §7.4)")
	}
}

// M1: an orphan scoped claim written straight to disk must NOT be indexed on replay.
func TestReplayDropsOrphan(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	orphan := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "motion:x"}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/vote"},
			"scope":     "sha256:unknownscope", "prev": "sha256:unknownprev",
			"by": "voter", "when": "2026-07-01T00:00:00+00:00",
		},
	}
	env, id := signHelper(t, priv, orphan)
	// Write it directly as an object file (simulating a git-merged/planted object).
	of := map[string]any{"claimId": id, "envelope": env}
	b, _ := json.MarshalIndent(of, "", "  ")
	hexid := id[len("sha256:"):]
	odir := filepath.Join(dir, "objects", "sha256")
	if err := os.MkdirAll(odir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(odir, hexid+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Claim(id); ok {
		t.Fatal("orphan scoped claim (unknown scope/prev) must be dropped on replay, not trusted")
	}
}

// TestScopeChain: a seed opens a scope; an in-scope claim chains to it; a claim naming a
// dangling prev is rejected (SPEC §7.4 tamper-evidence).
func TestScopeChain(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	sign := func(st map[string]any) (core.Envelope, string) {
		payload, err := core.CanonValue(st)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
		env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		env.Signatures = append(env.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{KeyID: "k", Sig: base64.StdEncoding.EncodeToString(sig)})
		return env, claim.ClaimID(payload)
	}

	seed := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "scope:pmx-board"}},
		"predicateType": claim.ScopePredicateType,
		"predicate": map[string]any{
			"predicate":   map[string]any{"uri": "https://kton.dev/v/scope"},
			"scope":       "pmx-board",
			"responsible": []any{"did:example:chair"},
			"genesis":     true,
			"by":          "did:example:chair",
			"when":        "2026-07-01T00:00:00+00:00",
		},
	}
	r, _ := registry.Open(dir)
	seedEnv, seedID := sign(seed)
	if _, _, err := r.Add(seedEnv); err != nil {
		t.Fatalf("seed add: %v", err)
	}

	// a valid in-scope claim whose prev is the seed
	child := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "motion:1"}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/vote-initialised"},
			"scope":     seedID,
			"prev":      seedID,
			"by":        "did:example:chair",
			"when":      "2026-07-01T00:01:00+00:00",
		},
	}
	childEnv, _ := sign(child)
	if _, _, err := r.Add(childEnv); err != nil {
		t.Fatalf("valid child add should pass: %v", err)
	}

	// a tampered claim: names the scope but a prev that does not resolve -> rejected
	bad := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "motion:2"}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/vote"},
			"scope":     seedID,
			"prev":      "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0",
			"by":        "did:example:chair",
			"when":      "2026-07-01T00:02:00+00:00",
		},
	}
	badEnv, badID := sign(bad)
	// A dangling prev is UNRESOLVED, not invalid (SPEC §11): it is PERSISTED - a later mirror of the
	// missing prev could resolve it - but DEFERRED, so it never joins the scope's chain and can never be
	// a head. That is what preserves tamper-evidence: a dropped/reordered link leaves its successors
	// unresolved rather than being silently accepted into the chain.
	if _, _, err := r.Add(badEnv); err != nil {
		t.Fatalf("a dangling-prev claim should be persisted (deferred), not rejected: %v", err)
	}
	heads, _, _ := r.Heads(seedID)
	for _, h := range heads {
		if h == badID {
			t.Fatal("a dangling-prev claim must NOT resolve into the scope or become a head (tamper-evidence)")
		}
	}
}

// TestTopLevelGenesisRejected: `genesis` is a structural flag that lives INSIDE a scope/v0 predicate
// (SPEC §7.4). A top-level `genesis:true` must not slip past the predicate-level guard and mint a
// scope back door (cold-session finding).
func TestTopLevelGenesisRejected(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "motion:x"}},
		"predicateType": claim.PredicateType,
		"genesis":       true, // top-level - never valid
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
			"by":        "someone", "when": "2026-07-01T00:00:00+00:00",
		},
	}
	env, _ := signHelper(t, priv, st)
	r, _ := registry.Open(dir)
	if _, _, err := r.Add(env); err == nil {
		t.Fatal("a top-level genesis:true must be rejected (SPEC §7.4)")
	}
}

// TestScopeHead: Heads returns the tip of a scope chain - the seed for an empty scope, the leaf
// for a linear chain, and every leaf for a branched scope (SPEC §7.4). The head is what a producer
// publishes/anchors to seal history, so it must be exact.
func TestScopeHead(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(st map[string]any) (core.Envelope, string) {
		payload, err := core.CanonValue(st)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
		env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		env.Signatures = append(env.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{KeyID: "k", Sig: base64.StdEncoding.EncodeToString(sig)})
		return env, claim.ClaimID(payload)
	}
	claimAt := func(subj, scope, prev string, min int) (core.Envelope, string) {
		return sign(map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"uri": subj}},
			"predicateType": claim.PredicateType,
			"predicate": map[string]any{
				"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
				"scope":     scope, "prev": prev,
				"by": "did:example:me", "when": "2026-07-01T00:0" + string(rune('0'+min)) + ":00+00:00",
			},
		})
	}

	r, _ := registry.Open(dir)
	seedEnv, seedID := sign(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"uri": "scope:hist"}},
		"predicateType": claim.ScopePredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/scope"},
			"scope":     "hist", "genesis": true,
			"by": "did:example:me", "when": "2026-07-01T00:00:00+00:00",
		},
	})
	if _, _, err := r.Add(seedEnv); err != nil {
		t.Fatalf("seed add: %v", err)
	}

	// (a) empty scope -> the seed is its own tip
	if h, n, ok := r.Heads(seedID); !ok || n != 0 || len(h) != 1 || h[0] != seedID {
		t.Fatalf("empty scope head = %v (n=%d ok=%v); want [seed] n=0", h, n, ok)
	}

	// (b) linear chain seed <- c1 <- c2 -> head is c2
	c1Env, c1 := claimAt("motion:1", seedID, seedID, 1)
	if _, _, err := r.Add(c1Env); err != nil {
		t.Fatalf("c1 add: %v", err)
	}
	c2Env, c2 := claimAt("motion:2", seedID, c1, 2)
	if _, _, err := r.Add(c2Env); err != nil {
		t.Fatalf("c2 add: %v", err)
	}
	if h, n, ok := r.Heads(seedID); !ok || n != 2 || len(h) != 1 || h[0] != c2 {
		t.Fatalf("linear head = %v (n=%d); want [%s] n=2", h, n, c2)
	}

	// (c) branch: cB also chains off c1 -> two heads {c2, cB}
	cBEnv, cB := claimAt("motion:3", seedID, c1, 3)
	if _, _, err := r.Add(cBEnv); err != nil {
		t.Fatalf("cB add: %v", err)
	}
	h, n, ok := r.Heads(seedID)
	if !ok || n != 3 || len(h) != 2 {
		t.Fatalf("branched head = %v (n=%d); want 2 heads n=3", h, n)
	}
	got := map[string]bool{h[0]: true, h[1]: true}
	if !got[c2] || !got[cB] {
		t.Fatalf("branched heads = %v; want {%s, %s}", h, c2, cB)
	}

	// unknown scope -> not ok
	if _, _, ok := r.Heads("sha256:deadbeef"); ok {
		t.Fatal("unknown scope must report ok=false")
	}
}

// TestObjectIDIsIndexable: an object given as {"id": X} (a DID, key IRI, OCI image, spectrum IRI - the
// most common object shape) must produce a non-empty Key so `nekton by object X` finds the claim. F4:
// the id field was unrecognized, so these claims rendered but were un-indexed.
func TestObjectIDIsIndexable(t *testing.T) {
	o := &claim.ObjOrLit{ID: "oci://rocker/r-ver:4.3.2@sha256:deadbeef"}
	if o.Key() != "oci://rocker/r-ver:4.3.2@sha256:deadbeef" {
		t.Fatalf("object {id:...} must be indexable, got %q", o.Key())
	}
	if (&claim.ObjOrLit{ID: "did:web:cro.example/people/qc"}).Key() == "" {
		t.Fatal("a DID id must be indexable")
	}
	// a uri still wins when present
	if (&claim.ObjOrLit{URI: "https://ex.example/thing", ID: "x"}).Key() == "x" {
		t.Fatal("uri must take precedence over id")
	}
}

// TestParseEnvelopeRejectsNonCanonical: the CLASS-BOUNDARY gate - a dup-key or imprecise-int payload is
// refused at parse (every ingest/read path), not handed a raw-bytes id by ClaimID's old fallback.
func TestParseEnvelopeRejectsNonCanonical(t *testing.T) {
	mk := func(payload string) core.Envelope {
		return core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload))}
	}
	for _, bad := range []string{
		`{"_type":"x","predicateType":"y","subject":[],"predicate":{"a":1,"a":2}}`,
		`{"_type":"x","predicateType":"y","subject":[],"predicate":{"n":9007199254740993}}`,
	} {
		if _, _, err := claim.ParseEnvelope(mk(bad)); err == nil {
			t.Errorf("ParseEnvelope must reject non-canonical payload: %s", bad)
		}
	}
	// a non-canonical payload gets a POISONED id that can't collide with any canonical claim id
	canonID := claim.ClaimID([]byte(`{"a":1}`))
	poison := claim.ClaimID([]byte(`{"a":1,"a":2}`))
	if canonID == poison {
		t.Error("a non-canonical payload must not share an id with a canonical one")
	}
}
