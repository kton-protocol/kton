package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/nekton/template"
)

// A claim id works as a subject (SPEC §7.1): a review of a claim is found by About(<claim id>), and in
// RDF its subject is the same content IRI the reviewed claim's nanopub derives from
// (https://kton.dev/o/<hex>), so the two join without any mapping (core round, MH 18.11.).
func TestClaimAboutAClaim(t *testing.T) {
	text := signedAbout(t, "urn:werk:text-1", map[string]any{"v": "draft"})
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := reg.Add(text)
	if err != nil {
		t.Fatal(err)
	}
	review, _, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{Hash: id}},
		Predicate: "https://kton.dev/v/reviewed", By: "reviewer-2", When: "2026-11-18T00:00:00Z",
		Object: map[string]any{"verdict": "approved"},
	}, seedKey("reviewer-2"))
	if err != nil {
		t.Fatal(err)
	}
	reviewID, _, err := reg.Add(review)
	if err != nil {
		t.Fatal(err)
	}
	about := reg.About(id)
	if len(about) != 1 || about[0].ClaimID != reviewID {
		t.Fatalf("About(%s) = %v, want the review %s", id, about, reviewID)
	}
	iri := "<https://kton.dev/o/" + strings.TrimPrefix(id, "sha256:") + ">"
	c := NewRecordContext(template.Set{})
	textQuads, err := Record(c, text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(textQuads), "<http://www.w3.org/ns/prov#wasDerivedFrom> "+iri) {
		t.Fatalf("the reviewed claim does not derive from %s:\n%s", iri, textQuads)
	}
	reviewQuads, err := Record(c, review)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reviewQuads), iri+" <https://kton.dev/v/reviewed> ") {
		t.Errorf("the review's subject is not %s:\n%s", iri, reviewQuads)
	}
}

// An upper-case content address projects to the same lower-case IRI (SPEC §14, #262 review O1).
func TestUpperCaseHashIsTheSameIRI(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	env := signedAbout(t, "urn:x", map[string]any{"file": "sha256:" + strings.ToUpper(hex)})
	st, _, _ := claim.ParseEnvelope(env)
	trig := RenderTrig(NewContext(template.Set{}, nil), st, map[string]any{"predicate": map[string]any{"uri": "https://kton.dev/v/x"},
		"object": map[string]any{"file": "sha256:" + strings.ToUpper(hex)}}, env, "x", "", "", "")
	if strings.Contains(trig, strings.ToUpper(hex)) || !strings.Contains(trig, hex) {
		t.Errorf("TriG keeps the upper-case address:\n%s", trig)
	}
	own, err := Record(NewRecordContext(template.Set{}), env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(own), strings.ToUpper(hex)) {
		t.Errorf("own quads keep the upper-case address:\n%s", own)
	}
}
