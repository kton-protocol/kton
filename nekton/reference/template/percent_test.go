package template_test

import (
	"testing"

	"kton.dev/nekton/template"
)

// kton-cockpit 25.11.: the template refuses a '%' that starts no %XX escape in its predicate,
// context and roles, and an iri field value with one is refused at Spec.
func TestTemplatePercentEncoding(t *testing.T) {
	for _, tpl := range []string{
		`{"name": "x", "predicate": "https://example.test/v/has%zz", "fields": {"state": {}}}`,
		`{"name": "x", "predicate": "https://example.test/v/p", "context": "https://example.test/c/%", "fields": {"state": {}}}`,
		`{"name": "x", "predicate": "https://example.test/v/p", "signerRoles": ["https://example.test/r/%zz"], "fields": {"state": {}}}`,
	} {
		set, _ := template.New(map[string][]byte{"x": []byte(tpl)}, nil)
		if _, ok := set.Get("x"); ok {
			t.Errorf("loaded: %s", tpl)
		}
		if r := set.RefusedReason("x"); r == "" {
			t.Errorf("no refusal reason for %s", tpl)
		}
	}
	set, _ := template.New(map[string][]byte{"x": []byte(`{"name": "x", "predicate": "https://example.test/v/p%2Fq",
		"fields": {"see": {"type": "iri"}}}`)}, nil)
	if _, ok := set.Get("x"); !ok {
		t.Fatalf("a valid %%2F refused: %q", set.RefusedReason("x"))
	}
	if _, err := set.Spec("x", "urn:doc:1", map[string]string{"see": "https://example.test/a%zz"}, nil); err == nil {
		t.Error("an iri value with %zz was accepted")
	}
	if _, err := set.Spec("x", "urn:doc:1", map[string]string{"see": "https://example.test/a%25"}, nil); err != nil {
		t.Errorf("an iri value with %%25: %v", err)
	}
}
