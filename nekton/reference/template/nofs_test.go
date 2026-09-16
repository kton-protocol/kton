package template_test

import (
	"encoding/json"
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

// The whole point of the rebuild: a caller with no filesystem gets a usable Set and a usable Spec.
// Nothing below touches a disk, so this is the path a browser cockpit takes.
func TestUsableWithoutAFilesystem(t *testing.T) {
	tmpl, _ := json.Marshal(map[string]any{
		"predicate": "qa:reviewed",
		"fields": map[string]any{
			"outcome": map[string]any{"type": "string", "required": true},
			"report":  map[string]any{"type": "file", "role": "evidence"},
		},
	})
	aliases, _ := json.Marshal(map[string]any{
		"prefixes": map[string]string{"qa": "https://kton.dev/v/qa/"},
	})
	s, err := template.New(map[string][]byte{"qa/review": tmpl}, aliases)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Names(); len(got) != 1 || got[0] != "qa/review" {
		t.Fatalf("Names = %v", got)
	}
	if _, ok := s.Get("qa/review"); !ok {
		t.Fatal("Get found nothing")
	}
	spec, err := s.Spec("qa/review", "sha256:"+strings.Repeat("c", 64),
		map[string]string{"outcome": "pass"}, map[string][]byte{"report": []byte("uploaded bytes")})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Predicate != "https://kton.dev/v/qa/reviewed" {
		t.Errorf("predicate = %q, want it resolved", spec.Predicate)
	}
	if len(spec.Evidence) != 1 {
		t.Errorf("evidence = %v, want the uploaded bytes hashed in", spec.Evidence)
	}
}
