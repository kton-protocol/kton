package template_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

// A template with a JSON mistake is named with its parse error, not as "not a template" (#186).
func TestSkipReasonSaysWhichKind(t *testing.T) {
	set, err := template.New(map[string][]byte{
		"qa-review": []byte(`{"name": "qa/review", "predicate": "qa:reviewed", "fields": []}`),
		"notes":     []byte(`{"title": "not a template"}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := set.SkipReason("qa-review"); !strings.Contains(r, "not valid template JSON") || !strings.Contains(r, "fields") {
		t.Errorf("broken template: %q, want the parse error", r)
	}
	if r := set.SkipReason("notes"); !strings.Contains(r, "not a template") {
		t.Errorf("stray file: %q", r)
	}
}
