package nanopub

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

// kton-review N2 on #314: the projection refuses an IRI that is no IRI as written instead of
// percent-encoding it, so "…/a b" and "…/a%20b" can no longer become one predicate.
func TestRecordRefusesRatherThanEncodes(t *testing.T) {
	ctx := NewRecordContext(template.Set{})
	if out, err := Record(ctx, signedBefore(t, "urn:doc:1", "https://example.org/a b", map[string]any{"v": "1"})); err == nil {
		t.Errorf("a predicate with a space projected:\n%s", out)
	}
	if out, err := Record(ctx, signedBefore(t, "https://example.org/s x", "https://example.org/p", map[string]any{"v": "1"})); err == nil {
		t.Errorf("a subject with a space projected:\n%s", out)
	}
	out, err := Record(ctx, signedBefore(t, "urn:doc:1", "https://example.org/a%20b", map[string]any{"v": "1"}))
	if err != nil || !strings.Contains(string(out), "<https://example.org/a%20b>") {
		t.Errorf("the genuine a%%20b predicate: %v\n%s", err, out)
	}
}

// kton-review N1 on #314: an object string that is no valid IRI is a literal, and does not take its
// claim out of the projection.
func TestObjectWithLonePercentIsALiteral(t *testing.T) {
	out, err := Record(NewRecordContext(template.Set{}), signedAbout(t, "urn:doc:1", map[string]any{"see": "https://example.org/a%zz"}))
	if err != nil {
		t.Fatalf("the claim was refused for an object value: %v", err)
	}
	if strings.Contains(string(out), "<https://example.org/a%zz>") || !strings.Contains(string(out), `"https://example.org/a%zz"`) {
		t.Errorf("the value is not a literal:\n%s", out)
	}
}
