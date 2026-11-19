package template_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

// kton-review 19.11. (found through cockpit #164): an alias must not redirect what a template signs.

var twoTemplates = map[string][]byte{
	"deviation": []byte(`{"name":"deviation","predicate":"urn:qm:deviation","fields":{"note":{}}}`),
	"other":     []byte(`{"name":"other","predicate":"urn:qm:other","fields":{"note":{}}}`),
}

// A template alias that takes a template's own name is refused at load, naming both.
func TestTemplateAliasMayNotTakeATemplatesName(t *testing.T) {
	_, err := template.New(twoTemplates, []byte(`{"templates":{"deviation":"other"}}`))
	if err == nil || !strings.Contains(err.Error(), `"deviation"`) {
		t.Fatalf("alias deviation -> other over a template named deviation: %v, want a refusal", err)
	}
	// an alias with a name of its own still works
	s, err := template.New(twoTemplates, []byte(`{"templates":{"dev":"deviation"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tm, ok := s.Get("dev"); !ok || tm.Predicate != "urn:qm:deviation" {
		t.Errorf("Get(dev) = %v %v", tm.Predicate, ok)
	}
}

// A prefix named after an IRI scheme is refused, whatever its case.
func TestPrefixAliasMayNotNameAnIRIScheme(t *testing.T) {
	for _, p := range []string{"urn", "URN", "https", "http", "did", "tag", "mailto"} {
		_, err := template.New(twoTemplates, []byte(`{"prefixes":{"`+p+`":"https://x/"}}`))
		if err == nil || !strings.Contains(err.Error(), "IRI scheme") {
			t.Errorf("prefix %q: %v, want a refusal", p, err)
		}
	}
	if _, err := template.New(twoTemplates, []byte(`{"terms":{"urn:qm:other":"urn:qm:x"}}`)); err == nil {
		t.Error("a term named after an absolute IRI was accepted")
	}
}

// A urn: predicate is signed as the template wrote it; Resolve leaves absolute IRIs alone.
func TestAbsolutePredicateIsSignedAsWritten(t *testing.T) {
	s, err := template.New(twoTemplates, []byte(`{"prefixes":{"qm":"https://x/"}}`))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := s.Spec("deviation", "urn:s", map[string]string{"note": "n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Predicate != "urn:qm:deviation" {
		t.Errorf("predicate = %s, want urn:qm:deviation", spec.Predicate)
	}
	for _, x := range []string{"urn:qm:a", "tag:x.org,2026:a", "https://x/a", "did:web:x", "mailto:a@b"} {
		if r := s.Resolve(x); r != x {
			t.Errorf("Resolve(%s) = %s", x, r)
		}
	}
	if r := s.Resolve("qm:a"); r != "https://x/a" {
		t.Errorf("a CURIE still resolves: %s", r)
	}
}
