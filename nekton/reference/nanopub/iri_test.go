package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

func signedAbout(t *testing.T, subject string, object map[string]any) core.Envelope {
	t.Helper()
	env, _, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: subject}},
		Predicate: "https://kton.dev/v/reviewed", By: "reviewer", When: "2026-10-25T00:00:00Z",
		Object: object,
	}, seedKey("reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestAbsoluteIRI(t *testing.T) {
	for _, ok := range []string{"urn:werk:kton-video", "tag:kton.dev,2026:x", "did:key:z6Mk", "mailto:a@b.example", "https://x.example/a", "urn:asifism:drama:v1:Modified"} {
		if !absoluteIRI(ok) {
			t.Errorf("absoluteIRI(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "10:30", "Note: foo", "a:b c", "urn:", ":x", "-a:b", "urn:a>b", "plain"} {
		if absoluteIRI(bad) {
			t.Errorf("absoluteIRI(%q) = true, want false", bad)
		}
	}
}

// A subject is a Ref, so an absolute IRI without "://" is an IRI in both faces. It was a literal in
// subject position, and the per-record projection refused the claim.
func TestURNSubjectProjectsAsIRI(t *testing.T) {
	env := signedAbout(t, "urn:werk:kton-video", map[string]any{
		"status": "urn:asifism:drama:v1:Modified",
		"note":   "Note:foo",
		"time":   "10:30",
		"link":   "https://x.example/a",
	})
	own, err := Record(NewRecordContext(template.Set{}), env)
	if err != nil {
		t.Fatalf("Record refused a urn subject: %v", err)
	}
	for _, want := range []string{
		"<urn:werk:kton-video> <https://kton.dev/v/reviewed> ",
		// object field values keep their rule: only a value with "://" is an IRI
		`"urn:asifism:drama:v1:Modified"`, `"Note:foo"`, `"10:30"`, "<https://x.example/a>",
	} {
		if !strings.Contains(string(own), want) {
			t.Errorf("own quads lack %s:\n%s", want, own)
		}
	}

	st, _, err := claim.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	trig := RenderTrig(NewContext(template.Set{}, nil), st, map[string]any{"predicate": map[string]any{"uri": "https://kton.dev/v/reviewed"}}, env, "x", "", "", "")
	if !strings.Contains(trig, "<urn:werk:kton-video> nk:reviewed sub:o .") {
		t.Errorf("TriG subject is not the IRI:\n%s", trig)
	}
}

// A subject that is no IRI is refused by Record and named by RegistryReport, not dropped silently.
func TestNonIRISubjectIsReported(t *testing.T) {
	bad := signedAbout(t, "kton video", map[string]any{"v": "x"})
	if _, err := Record(NewRecordContext(template.Set{}), bad); err == nil {
		t.Error("Record accepted a subject that is no IRI")
	}

	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	badID, _, err := reg.Add(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Add(signedAbout(t, "urn:werk:kton-video", map[string]any{"v": "x"})); err != nil {
		t.Fatal(err)
	}
	trig, n, skipped := RegistryReport(reg, NewContext(template.Set{}, nil))
	if n != 1 || len(skipped) != 1 || skipped[0].ClaimID != badID || !strings.Contains(skipped[0].Reason, "kton video") {
		t.Fatalf("n = %d, skipped = %+v; want 1 rendered and %s skipped", n, skipped, badID)
	}
	if strings.Contains(trig, `"kton video" `) {
		t.Errorf("the skipped claim is in the TriG:\n%s", trig)
	}
}
