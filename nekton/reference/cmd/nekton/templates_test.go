package main

import (
	"strings"
	"testing"
)

// `nekton templates` has no subcommands, but it used to read any positional as a template NAME with
// the last one winning. That made doc drift invisible in the worst way (#45, #46): `templates ls`
// answered `no template "ls"`, which reads as a typo in a name rather than an unknown verb, and the
// documented `templates show <name>` appeared to work only because <name> overwrote `show`. Any word
// would have done. Someone spot-checking the documentation against the binary had it confirmed.
func TestTemplatesRejectsSubcommandsInsteadOfReadingThemAsNames(t *testing.T) {
	for _, sub := range []string{"ls", "list", "show", "search", "pull", "push", "add"} {
		err := listTemplates([]string{sub})
		if err == nil {
			t.Errorf("templates %s was accepted", sub)
			continue
		}
		if !strings.Contains(err.Error(), "has no subcommand") {
			t.Errorf("templates %s: %v; want it named as an unknown subcommand, not as a missing template", sub, err)
		}
	}

	// Two names is the shape that made `templates show <name>` look right. Refuse it rather than
	// silently picking one.
	err := listTemplates([]string{"HUHU", "pmx/model-role"})
	if err == nil || !strings.Contains(err.Error(), "at most one template name") {
		t.Errorf("two positionals: %v; want a refusal naming both", err)
	}

	// A single unknown name is still the honest not-found error - this must not swallow that.
	err = listTemplates([]string{"definitely-not-a-template"})
	if err == nil || !strings.Contains(err.Error(), "no template") {
		t.Errorf("single unknown name: %v; want the not-found error", err)
	}
}
