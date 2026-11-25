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
		// kton-review R1 on #301: a role must resolve to an absolute IRI.
		{"role as a bare word", `"signerRoles": ["reviewer"], `, "does not resolve to an absolute IRI"},
		{"role with an undeclared prefix", `"signerRoles": ["zz:lead"], `, "does not resolve to an absolute IRI"},
		{"role with a leading space", `"signerRoles": [" role:lead"], `, "does not resolve to an absolute IRI"},
		{"role IRI with >", `"signerRoles": ["https://example.org/r>x"], `, "does not resolve to an absolute IRI"},
		{"role IRI with a space", `"signerRoles": ["https://example.org/r x"], `, "does not resolve to an absolute IRI"},
		// kton-review on kton-cockpit #262: control characters in a role, and none in the reason.
		{"role with an ESC sequence", `"signerRoles": ["https://example.org/r/\u001b[31mRED\u001b[0m"], `, "control characters"},
		{"role with ESC, twice", `"signerRoles": ["https://example.org/r/\u001bx", "https://example.org/r/\u001bx"], `, "control characters"},
		{"role with DEL", `"signerRoles": ["https://example.org/r/\u007fx"], `, "control characters"},
		{"role with a C1 control", `"signerRoles": ["https://example.org/r/\u009bx"], `, "control characters"},
		{"role with a line separator", `"signerRoles": ["https://example.org/r/\u2028x"], `, "control characters"},
		{"role with a right-to-left override", `"signerRoles": ["https://example.org/r/\u202ex"], `, "control characters"},
		{"role with a no-break space", `"signerRoles": ["https://example.org/r/\u00a0x"], `, "control characters"},
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
			r := set.RefusedReason("qa/review")
			if !strings.Contains(r, c.want) {
				t.Errorf("reason %q, want %q", r, c.want)
			}
			// A reason is printed to terminals: it must carry no control character from the file.
			for _, ch := range r {
				if ch < 0x20 || ch == 0x7f || (ch >= 0x80 && ch < 0xa0) || ch == 0x2028 || ch == 0x202e {
					t.Errorf("reason carries control character %U: %q", ch, r)
				}
			}
			if _, ok := set.Get("qa/note"); !ok {
				t.Error("the other template went down with it")
			}
		})
	}
}

// The duplicate-role reason quotes the resolved role (it printed it raw with %s), and a role with
// a non-ASCII but graphic character is still accepted.
func TestIntentDuplicateReasonIsQuoted(t *testing.T) {
	set, _ := template.New(map[string][]byte{"qa/review": intentTpl(
		`"signerRoles": ["role:a\"b", "https://example.org/role/a\"b"], `)}, []byte(intentAliases))
	if r := set.RefusedReason("qa/review"); !strings.Contains(r, "does not resolve") {
		t.Errorf("a quote in a role: %q", r)
	}
	set, _ = template.New(map[string][]byte{"qa/review": intentTpl(
		`"signerRoles": ["role:prüfer", "https://example.org/role/prüfer"], `)}, []byte(intentAliases))
	if r := set.RefusedReason("qa/review"); !strings.Contains(r, `names "https://example.org/role/prüfer" twice`) {
		t.Errorf("duplicate reason not quoted: %q", r)
	}
	set, _ = template.New(map[string][]byte{"qa/review": intentTpl(`"signerRoles": ["role:prüfer"], `)}, []byte(intentAliases))
	if _, ok := set.Get("qa/review"); !ok {
		t.Errorf("a graphic non-ASCII role was refused: %q", set.RefusedReason("qa/review"))
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
