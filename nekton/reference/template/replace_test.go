package template_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

const statusTpl = `{"name": "qm/status", "predicate": "qm:status", "replace": "previous",
  "fields": {"state": {"type": "string", "required": true}}}`

const claimID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// replace: previous makes the reserved field replaces available without declaring it, and only a
// claim id goes into it (#257).
func TestReplacePrevious(t *testing.T) {
	set, err := template.New(map[string][]byte{"qm/status": []byte(statusTpl)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tpl, ok := set.Get("qm/status")
	if !ok || tpl.Replace != "previous" {
		t.Fatalf("Get: %v %+v", ok, tpl)
	}
	spec, err := set.Spec("qm/status", "urn:doc:1", map[string]string{"state": "approved", "replaces": claimID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Object["replaces"] != claimID {
		t.Errorf("replaces not signed: %v", spec.Object)
	}
	if _, err := set.Spec("qm/status", "urn:doc:1", map[string]string{"state": "approved"}, nil); err != nil {
		t.Errorf("the first status has nothing to replace and must still sign: %v", err)
	}
	upper := "SHA256:" + strings.ToUpper(strings.TrimPrefix(claimID, "sha256:"))
	spec, err = set.Spec("qm/status", "urn:doc:1", map[string]string{"state": "x", "replaces": upper}, nil)
	if err != nil || spec.Object["replaces"] != claimID {
		t.Errorf("an upper-case id must be signed normalised: %v, %v", spec.Object["replaces"], err)
	}
	for _, bad := range []string{"urn:doc:0", "sha256:0123", "previous"} {
		if _, err := set.Spec("qm/status", "urn:doc:1", map[string]string{"state": "x", "replaces": bad}, nil); err == nil {
			t.Errorf("replaces = %q accepted", bad)
		}
	}
}

// Without replace, the reserved field is not there to fill.
func TestNoReplaceNoField(t *testing.T) {
	set, err := template.New(map[string][]byte{"qm/note": []byte(`{"name": "qm/note", "predicate": "qm:note", "fields": {"text": {"type": "string"}}}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Spec("qm/note", "urn:doc:1", map[string]string{"replaces": claimID}, nil); err == nil {
		t.Error("replaces accepted on a template that neither declares it nor says replace")
	}
}

func TestReplaceShapeRefused(t *testing.T) {
	set, err := template.New(map[string][]byte{
		"a": []byte(`{"name": "a", "predicate": "qm:a", "replace": "latest", "fields": {"x": {"type": "string"}}}`),
		"b": []byte(`{"name": "b", "predicate": "qm:b", "fields": {"replaces": {"type": "string"}}}`),
		"c": []byte(`{"name": "c", "predicate": "qm:c", "fields": {"replaces": {"type": "ref"}}}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(set.Refused()["a"], "latest") || !strings.Contains(set.Refused()["b"], "reserved") {
		t.Errorf("Refused() = %v", set.Refused())
	}
	if _, ok := set.Get("c"); !ok {
		t.Error("a template declaring replaces as ref was refused")
	}
}
