package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// A union must be COMMUTATIVE. §11-§12 promise a conflict-free set union, and an operation whose
// answer depends on the order of its arguments is not one.
//
// OpenUnion used to open dirs[0] normally - which settled it alone and DROPPED whatever did not
// resolve - and then settle only the remaining sources against that finished view. A scoped child in
// A whose seed lived in B was therefore discarded before B had even been read:
//
//	OpenUnion(child-only, seed-only) -> child NOT held, 1 unresolved
//	OpenUnion(seed-only, child-only) -> child held,     0 unresolved
//
// Same signed bytes, both times. This walks every permutation of a three-link chain across
// three stores and requires one identical answer.
func TestUnionResolvesAChainInAnySourceOrder(t *testing.T) {
	k := testKey(t)
	seed := seedClaim(t, k)
	seedID := envID(t, seed)
	link := scopedClaim(t, k, "link", seedID, seedID)
	linkID := envID(t, link)
	child := scopedClaim(t, k, "child", seedID, linkID)
	childID := envID(t, child)

	// One store per link, so no single source can resolve the chain alone.
	stores := map[string]core.Envelope{"seed": seed, "link": link, "child": child}
	dirs := map[string]string{}
	for name, env := range stores {
		d := t.TempDir()
		r, err := registry.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		dirs[name] = d
	}

	for _, order := range [][]string{
		{"seed", "link", "child"}, {"seed", "child", "link"},
		{"link", "seed", "child"}, {"link", "child", "seed"},
		{"child", "seed", "link"}, {"child", "link", "seed"},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			u, err := registry.OpenUnion(dirs[order[0]], dirs[order[1]], dirs[order[2]])
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{seedID, linkID, childID} {
				if _, ok := u.Claim(id); !ok {
					t.Errorf("claim %s is not held in source order %v - the union is not commutative", id, order)
				}
			}
			if n := u.Unresolved(seedID); n != 0 {
				t.Errorf("unresolved = %d, want 0: every dependency is present across the named sources", n)
			}
			if u.Len() != 3 {
				t.Errorf("union holds %d claims, want 3", u.Len())
			}
		})
	}

	// The other half of the same rule: a genuinely missing dependency must stay explicitly
	// unresolved rather than being quietly resolved or quietly dropped.
	t.Run("without the seed the chain stays unresolved", func(t *testing.T) {
		u, err := registry.OpenUnion(dirs["child"], dirs["link"])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := u.Claim(childID); ok {
			t.Error("the child resolved without its scope seed")
		}
		if u.Unresolved(seedID) == 0 {
			t.Error("a withheld seed must leave the scope reported as unresolved, not silently empty")
		}
	})
}

// Two sources hold the SAME canonical claim - identical signed payload bytes - signed by
// different keys. That is one claim with two signatures, which is what Add already does at ingest.
// settle discarded the second, so the surviving co-signer depended on argument order and BySigner
// could not find the other.
func TestUnionKeepsEveryCoSignature(t *testing.T) {
	ka, kb := testKey(t), testKey(t)
	envA := unscopedClaimSignedBy(t, ka)
	envB := unscopedClaimSignedBy(t, kb)
	if envA.Payload != envB.Payload {
		t.Fatal("the fixture must sign IDENTICAL payload bytes - otherwise this is the documented differing-payload case, not a twin")
	}
	id := envID(t, envA)

	dirA, dirB := t.TempDir(), t.TempDir()
	for d, env := range map[string]core.Envelope{dirA: envA, dirB: envB} {
		r, err := registry.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Add(env); err != nil {
			t.Fatal(err)
		}
	}

	keyA := core.KeyIDHex(ka.Public().(ed25519.PublicKey))
	keyB := core.KeyIDHex(kb.Public().(ed25519.PublicKey))
	for _, order := range [][2]string{{dirA, dirB}, {dirB, dirA}} {
		u, err := registry.OpenUnion(order[0], order[1])
		if err != nil {
			t.Fatal(err)
		}
		rec, ok := u.Claim(id)
		if !ok {
			t.Fatal("the claim is not held")
		}
		if n := len(rec.Envelope.Signatures); n != 2 {
			t.Errorf("%d signature(s) survived the union, want 2 - a co-signer was dropped", n)
		}
		if len(u.BySigner(keyA)) != 1 || len(u.BySigner(keyB)) != 1 {
			t.Errorf("BySigner finds A:%d B:%d, want 1 and 1 - the signer index lost a co-signer",
				len(u.BySigner(keyA)), len(u.BySigner(keyB)))
		}
	}
}

// Material attached in the SECOND source must not vanish - a union that keeps only the first
// source's is not a union. §8.1 makes PRODUCING material optional; silently losing evidence the
// named sources hold, through an advertised union API, is a different thing.
func TestUnionMergesMaterialFromEverySource(t *testing.T) {
	k := testKey(t)
	env := unscopedClaimSignedBy(t, k)
	id := envID(t, env)

	withRecord, withMaterial, empty := t.TempDir(), t.TempDir(), t.TempDir()
	r, err := registry.Open(withRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	// The attachment lives in a DIFFERENT store from the record: material is attached out of band
	// and after the fact, so this is the normal case, not an exotic one.
	m, err := registry.Open(withMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Add(env); err != nil {
		t.Fatal(err)
	}
	att := registry.VerificationMaterial{Subject: id, Scheme: "test-scheme", Material: "eA=="}
	if err := m.AttachMaterial(att); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Open(empty); err != nil {
		t.Fatal(err)
	}

	for name, dirs := range map[string][]string{
		"record first":   {withRecord, withMaterial},
		"material first": {withMaterial, withRecord},
		"empty in front": {empty, withMaterial},
		"empty behind":   {withMaterial, empty},
		"both sources":   {withMaterial, withMaterial},
	} {
		t.Run(name, func(t *testing.T) {
			u, err := registry.OpenUnion(dirs...)
			if err != nil {
				t.Fatal(err)
			}
			got := u.Material(id)
			if len(got) != 1 {
				t.Fatalf("%d attachment(s), want exactly 1 (identical evidence must not double either)", len(got))
			}
			if got[0].Scheme != "test-scheme" {
				t.Errorf("scheme = %q, want the attached one carried through", got[0].Scheme)
			}
		})
	}
}

// ---- fixtures ----

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func sign(t *testing.T, v any, k ed25519.PrivateKey) core.Envelope {
	t.Helper()
	raw, err := core.CanonValue(v)
	if err != nil {
		t.Fatal(err)
	}
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(raw)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(k.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(ed25519.Sign(k, core.PAE(core.PayloadType, raw)))})
	return env
}

func envID(t *testing.T, env core.Envelope) string {
	t.Helper()
	b, err := env.PayloadBytes()
	if err != nil {
		t.Fatal(err)
	}
	return claim.ClaimID(b)
}

func seedClaim(t *testing.T, k ed25519.PrivateKey) core.Envelope {
	t.Helper()
	return sign(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": claim.ScopePredicateType,
		"predicate":     map[string]any{"genesis": true},
	}, k)
}

func claimBody(why string) map[string]any {
	return map[string]any{
		"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
		"by":        "CN=a", "when": "2026-07-16T00:00:00Z", "why": why,
	}
}

func statement(p map[string]any) map[string]any {
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"sha256": strings.Repeat("ab", 32)}}},
		"predicateType": claim.PredicateType,
		"predicate":     p,
	}
}

func scopedClaim(t *testing.T, k ed25519.PrivateKey, why, scope, prev string) core.Envelope {
	t.Helper()
	p := claimBody(why)
	p["scope"], p["prev"] = scope, prev
	return sign(t, statement(p), k)
}

// unscopedClaimSignedBy produces IDENTICAL payload bytes for any key, so two of them are a twin -
// the same claim with two signatures - rather than two different claims.
func unscopedClaimSignedBy(t *testing.T, k ed25519.PrivateKey) core.Envelope {
	t.Helper()
	return sign(t, statement(claimBody("same statement")), k)
}
