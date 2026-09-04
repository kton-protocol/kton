package claim_test

import (
	"encoding/json"
	"testing"

	"kton.dev/nekton/claim"
)

// statementWith builds a parsed Statement + Predicate carrying one subject, so a test can exercise
// Validate on the WIRE form (which is what ingest sees) rather than on the authoring spec.
func statementWith(t *testing.T, subject map[string]any) (*claim.Statement, *claim.Predicate) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{subject},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
			"by":        "CN=a",
			"when":      "2026-07-16T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var st claim.Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	p, err := st.ParsePredicate()
	if err != nil {
		t.Fatal(err)
	}
	return &st, p
}
