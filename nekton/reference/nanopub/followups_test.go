package nanopub

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/nekton/template"
)

// #210 follow-ups of the RDF projections.

func TestDeferredClaimIsSkippedAndNamed(t *testing.T) {
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	missing := "sha256:" + strings.Repeat("9", 64)
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/x",
		By: "b", When: "2026-11-18T00:00:00Z", Scope: missing, Prev: missing}, seedKey("a"))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := reg.Add(env)
	if err != nil {
		t.Fatal(err)
	}
	trig, n, skipped := RegistryReport(reg, NewContext(template.Set{}, nil))
	if n != 0 || len(skipped) != 1 || skipped[0].ClaimID != id || !strings.Contains(skipped[0].Reason, "deferred") {
		t.Fatalf("n=%d skipped=%+v trig=%s", n, skipped, trig)
	}
}

func TestCoSignedClaimOnceWithEverySigner(t *testing.T) {
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec := claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:x"}}, Predicate: "https://kton.dev/v/reviewed", By: "b", When: "2026-11-18T00:00:00Z"}
	var keys []ed25519.PublicKey
	for _, k := range []string{"a", "b"} {
		env, _, err := claim.SignWith(spec, seedKey(k))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reg.Add(env); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, seedKey(k).Public().(ed25519.PublicKey))
	}
	trig, n, _ := RegistryReport(reg, NewContext(template.Set{}, keys))
	if n != 1 || strings.Count(trig, "sub:Head {") != 1 {
		t.Fatalf("rendered %d claims / %d heads, want one:\n%s", n, strings.Count(trig, "sub:Head {"), trig)
	}
	if c := strings.Count(trig, "prov:wasAttributedTo"); c != 2 {
		t.Errorf("%d attributions, want both trusted co-signers:\n%s", c, trig)
	}
}

func TestBlankKeyidIsNotASharedAgent(t *testing.T) {
	env := signedAbout(t, "urn:x", map[string]any{"v": "1"})
	env.Signatures[0].KeyID = ""
	st, _, err := claim.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	trig := RenderTrig(NewContext(template.Set{}, nil), st, map[string]any{"by": "reviewer", "predicate": map[string]any{"uri": "https://kton.dev/v/reviewed"}}, env, "x", "", "", "")
	if strings.Contains(trig, "claimedSigner agent: ") || strings.Contains(trig, "claimedSigner <https://kton.dev/agent/>") ||
		!strings.Contains(trig, "nk:claimedSigner agent:") {
		t.Errorf("a blank keyid became the shared agent/ node:\n%s", trig)
	}
}

func TestLonePercentIsEscaped(t *testing.T) {
	for in, want := range map[string]string{"a%zz": "a%25zz", "a%2": "a%252", "a%20b": "a%20b", "a b": "a%20b", "100%": "100%25"} {
		if got := iriEsc(in); got != want {
			t.Errorf("iriEsc(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptyAndNestedLists(t *testing.T) {
	env := signedAbout(t, "urn:x", map[string]any{"tags": []any{}, "m": []any{[]any{"1", "2"}, []any{"3"}}, "flat": []any{"a", "b"}})
	own, err := Record(NewRecordContext(template.Set{}), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<http://www.w3.org/1999/02/22-rdf-syntax-ns#nil>",
		"<http://www.w3.org/1999/02/22-rdf-syntax-ns#Seq>",
		"<http://www.w3.org/1999/02/22-rdf-syntax-ns#_2>",
	} {
		if !strings.Contains(string(own), want) {
			t.Errorf("own quads lack %s:\n%s", want, own)
		}
	}
}
