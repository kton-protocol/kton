package main

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

// #300: templates --show prints the advisory intent, roles resolved through the aliases.
func TestShowTemplateIntent(t *testing.T) {
	scope := template.ScopeIRIPrefix + strings.Repeat("ab", 32)
	set, err := template.New(map[string][]byte{"qa/review": []byte(`{"name": "qa/review", "predicate": "qa:reviewed",
		"signerRoles": ["role:qa-reviewer"], "scopes": ["` + scope + `"], "fields": {"outcome": {}}}`)},
		[]byte(`{"prefixes": {"qa": "https://example.org/qa/", "role": "https://example.org/role/"}}`))
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := showTemplate(set, "qa/review"); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"signers:   https://example.org/role/qa-reviewer  (intended roles, advisory)",
		"scopes:    " + scope + "  (intended, advisory)"} {
		if !strings.Contains(out, want) {
			t.Errorf("--show lacks %q:\n%s", want, out)
		}
	}
	plain, _ := template.New(map[string][]byte{"qa/note": []byte(`{"name": "qa/note", "predicate": "qa:note", "fields": {"t": {}}}`)}, nil)
	out = captureStdout(t, func() { showTemplate(plain, "qa/note") })
	if strings.Contains(out, "signers:") || strings.Contains(out, "scopes:") {
		t.Errorf("a template without intent printed intent lines:\n%s", out)
	}
}
