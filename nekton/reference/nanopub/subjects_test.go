package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/nekton/template"
)

// A claim signed about several subjects asserts the predicate of every one of them, in the published
// TriG and in the per-record quads. Only the first was asserted, so the projection said less than the
// signature and a SPARQL rule over it never saw the others (#253).
func TestEverySubjectIsAsserted(t *testing.T) {
	subjects := []string{"urn:werk:a", "urn:werk:b", "urn:werk:c"}
	var specs []claim.SubjectSpec
	for _, s := range subjects {
		specs = append(specs, claim.SubjectSpec{URI: s})
	}
	env, _, err := claim.SignWith(claim.Spec{
		Subject:   specs,
		Predicate: "https://kton.dev/v/reviewed", By: "reviewer", When: "2026-11-18T00:00:00Z",
		Object: map[string]any{"verdict": "approved"},
	}, seedKey("reviewer"))
	if err != nil {
		t.Fatal(err)
	}

	own, err := Record(NewRecordContext(template.Set{}), env)
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := claim.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	trig := RenderTrig(NewContext(template.Set{}, nil), st, map[string]any{"predicate": map[string]any{"uri": "https://kton.dev/v/reviewed"}}, env, "x", "", "", "")
	for _, s := range subjects {
		if !strings.Contains(string(own), "<"+s+"> <https://kton.dev/v/reviewed> ") {
			t.Errorf("own quads lack subject %s:\n%s", s, own)
		}
		if !strings.Contains(trig, "<"+s+"> nk:reviewed sub:o .") {
			t.Errorf("TriG lacks subject %s:\n%s", s, trig)
		}
	}
}

// One subject renders exactly as before: the change adds triples only for claims that have more.
func TestOneSubjectUnchanged(t *testing.T) {
	env := signedAbout(t, "urn:werk:kton-video", map[string]any{"v": "x"})
	own, err := Record(NewRecordContext(template.Set{}), env)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(own), "<https://kton.dev/v/reviewed> "); n != 1 {
		t.Errorf("%d assertion quads for one subject, want 1:\n%s", n, own)
	}
}

// One subject that is no IRI skips the whole claim and names that subject: rendering it would put a
// literal in subject position, and a strict store refuses the entire registry document (kton-review
// N1 on #254).
func TestNonIRISecondSubjectIsSkipped(t *testing.T) {
	env, _, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:werk:a"}, {URI: "kton video"}},
		Predicate: "https://kton.dev/v/reviewed", By: "reviewer", When: "2026-11-18T00:00:00Z",
		Object: map[string]any{"v": "x"},
	}, seedKey("reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Record(NewRecordContext(template.Set{}), env); err == nil {
		t.Error("Record accepted a claim with a non-IRI second subject")
	}
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	badID, _, err := reg.Add(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Add(signedAbout(t, "urn:werk:kton-video", map[string]any{"v": "x"})); err != nil {
		t.Fatal(err)
	}
	trig, n, skipped := RegistryReport(reg, NewContext(template.Set{}, nil))
	if n != 1 || len(skipped) != 1 || skipped[0].ClaimID != badID || !strings.Contains(skipped[0].Reason, "kton video") {
		t.Fatalf("n = %d, skipped = %+v; want 1 rendered and %s skipped naming the subject", n, skipped, badID)
	}
	if strings.Contains(trig, `"kton video"`) {
		t.Errorf("a literal subject reached the TriG:\n%s", trig)
	}
}
