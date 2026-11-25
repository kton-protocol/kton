package template_test

import (
	"reflect"
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

const seedIRI = "https://kton.dev/o/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func intentTpl(extra string) []byte {
	return []byte(`{"name": "qa/review", "predicate": "qa:reviewed", ` + extra +
		`"fields": {"outcome": {"type": "enum", "values": ["pass", "fail"], "required": true}}}`)
}

const intentAliases = `{"prefixes": {"qa": "https://example.org/qa/", "role": "https://example.org/role/"}}`

// #300: signerRoles and scopes load and are readable, and they change nothing about the claim: the
// spec built from a template with them equals the one built without them.
func TestIntentIsAdvisory(t *testing.T) {
	with, err := template.New(map[string][]byte{"qa/review": intentTpl(
		`"signerRoles": ["role:qa-reviewer", "https://example.org/role/lead"], "scopes": ["` + seedIRI + `"], `)},
		[]byte(intentAliases))
	if err != nil {
		t.Fatal(err)
	}
	tpl, ok := with.Get("qa/review")
	if !ok {
		t.Fatalf("not loaded; refused: %v", with.Refused())
	}
	if !reflect.DeepEqual(tpl.SignerRoles, []string{"role:qa-reviewer", "https://example.org/role/lead"}) ||
		!reflect.DeepEqual(tpl.Scopes, []string{seedIRI}) {
		t.Errorf("intent: %+v %+v", tpl.SignerRoles, tpl.Scopes)
	}
	without, _ := template.New(map[string][]byte{"qa/review": intentTpl("")}, []byte(intentAliases))
	vals := map[string]string{"outcome": "pass"}
	a, err := with.Spec("qa/review", "urn:doc:1", vals, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := without.Spec("qa/review", "urn:doc:1", vals, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the intent keys changed the claim spec:\n%+v\n%+v", a, b)
	}
}

// Each refusal names its reason, refuses only that template, and leaves the rest of the set working.
func TestIntentRefusals(t *testing.T) {
	cases := []struct{ name, extra, want string }{
		{"empty role", `"signerRoles": [""], `, "empty entry"},
		{"role twice", `"signerRoles": ["role:a", "role:a"], `, "twice"},
		{"role twice after resolution", `"signerRoles": ["role:a", "https://example.org/role/a"], `, "twice"},
		{"scope by name", `"scopes": ["qa"], `, "not a scope seed IRI"},
		{"scope as a claim id", `"scopes": ["sha256:` + strings.TrimPrefix(seedIRI, template.ScopeIRIPrefix) + `"], `, "not a scope seed IRI"},
		{"scope upper-case hex", `"scopes": ["` + strings.ToUpper(seedIRI[len(template.ScopeIRIPrefix):]) + `"], `, "not a scope seed IRI"},
		{"scope short hex", `"scopes": ["` + seedIRI[:len(seedIRI)-1] + `"], `, "not a scope seed IRI"},
		{"scope twice", `"scopes": ["` + seedIRI + `", "` + seedIRI + `"], `, "twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := template.New(map[string][]byte{
				"qa/review": intentTpl(c.extra),
				"qa/note":   []byte(`{"name": "qa/note", "predicate": "qa:note", "fields": {"text": {}}}`),
			}, []byte(intentAliases))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := set.Get("qa/review"); ok {
				t.Fatal("loaded")
			}
			if r := set.RefusedReason("qa/review"); !strings.Contains(r, c.want) {
				t.Errorf("reason %q, want %q", r, c.want)
			}
			if _, ok := set.Get("qa/note"); !ok {
				t.Error("the other template went down with it")
			}
		})
	}
}

// A value of the wrong JSON type is not valid template JSON: the file is skipped with the parse error,
// like any other mistyped key.
func TestIntentWrongTypeIsSkipped(t *testing.T) {
	for _, extra := range []string{`"signerRoles": "role:a", `, `"scopes": [1], `} {
		set, err := template.New(map[string][]byte{"qa/review": intentTpl(extra)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := set.Get("qa/review"); ok || !strings.Contains(set.SkipReason("qa/review"), "not valid template JSON") {
			t.Errorf("%s: skip reason %q", extra, set.SkipReason("qa/review"))
		}
	}
}
