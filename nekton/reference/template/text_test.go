package template_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

func noControl(t *testing.T, what, s string) {
	t.Helper()
	for _, c := range s {
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == 0x2028 || c == 0x202e {
			t.Errorf("%s carries control character %U: %q", what, c, s)
		}
	}
}

// kton-review follow-up on #306: an escape sequence in a template's predicate, context, field name
// or enum value is refused at load (each is printed or signed), with the value quoted in the reason.
func TestTemplateTextRefusals(t *testing.T) {
	cases := []struct{ name, tpl, want string }{
		{"predicate with ESC", `{"name": "x", "predicate": "https://example.org/p/\u001b[31mX", "fields": {"a": {}}}`, `"predicate"`},
		{"predicate resolving to ESC", `{"name": "x", "predicate": "qa:\u001bX", "fields": {"a": {}}}`, `"predicate"`},
		{"predicate with U+202E", `{"name": "x", "predicate": "https://example.org/p/\u202eX", "fields": {"a": {}}}`, `"predicate"`},
		{"predicate with a space", `{"name": "x", "predicate": "https://example.org/p q", "fields": {"a": {}}}`, `"predicate"`},
		{"context with ESC", `{"name": "x", "predicate": "qa:p", "context": "https://example.org/c/\u001bX", "fields": {"a": {}}}`, `"context"`},
		{"field name with ESC", `{"name": "x", "predicate": "qa:p", "fields": {"a\u001b[31m": {}}}`, "field name"},
		{"enum value with ESC", `{"name": "x", "predicate": "qa:p", "fields": {"a": {"type": "enum", "values": ["ok", "b\u001bX"]}}}`, "enum value"},
		{"enum value with a newline", `{"name": "x", "predicate": "qa:p", "fields": {"a": {"type": "enum", "values": ["b\nX"]}}}`, "enum value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := template.New(map[string][]byte{"x": []byte(c.tpl)}, []byte(`{"prefixes": {"qa": "https://example.org/qa/"}}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := set.Get("x"); ok {
				t.Fatal("loaded")
			}
			r := set.RefusedReason("x")
			if !strings.Contains(r, c.want) {
				t.Errorf("reason %q, want %q", r, c.want)
			}
			noControl(t, "the reason", r)
		})
	}
}

// A template NAME with a control character is skipped, not refused: refusals are keyed by name, so
// Refused() would hand the escape sequence back to whoever prints it.
func TestTemplateNameWithControlIsSkipped(t *testing.T) {
	set, err := template.New(map[string][]byte{"f": []byte(`{"name": "n\u001b[31mX", "predicate": "https://example.org/p", "fields": {"a": {}}}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Names()) != 0 || len(set.Refused()) != 0 {
		t.Fatalf("names %q, refused %q", set.Names(), set.Refused())
	}
	r := set.SkipReason("f")
	if !strings.Contains(r, "control character") {
		t.Errorf("skip reason %q", r)
	}
	noControl(t, "the skip reason", r)
}

// Graphic text still loads: a non-ASCII enum value, an enum value with a space, a non-ASCII
// predicate path.
func TestTemplateGraphicTextLoads(t *testing.T) {
	set, _ := template.New(map[string][]byte{"x": []byte(`{"name": "qa/prüfung", "predicate": "https://example.org/p/prüfung",
		"fields": {"ergebnis": {"type": "enum", "values": ["bestanden", "nicht zutreffend"]}}}`)}, nil)
	if _, ok := set.Get("qa/prüfung"); !ok {
		t.Errorf("refused: %q, skipped %q", set.RefusedReason("qa/prüfung"), set.Skipped())
	}
}

// An `iri` field value with a control character is refused at Spec, as the template's own IRIs are.
func TestIRIFieldRefusesControl(t *testing.T) {
	set, _ := template.New(map[string][]byte{"x": []byte(`{"name": "x", "predicate": "https://example.org/p", "fields": {"see": {"type": "iri"}}}`)}, nil)
	for _, v := range []string{"https://example.org/a\u001bX", "urn:x:\u202ey"} {
		if _, err := set.Spec("x", "urn:doc:1", map[string]string{"see": v}, nil); err == nil {
			t.Errorf("iri value %q accepted", v)
		}
	}
	if _, err := set.Spec("x", "urn:doc:1", map[string]string{"see": "https://example.org/ok"}, nil); err != nil {
		t.Errorf("a clean iri value: %v", err)
	}
}

// kton-review N2 on #301: "://" alone does not make an IRI; the scheme must be one.
func TestAbsoluteIRINeedsAScheme(t *testing.T) {
	aliases := []byte(`{"prefixes": {"role": "https://example.org/role/"}}`)
	for _, role := range []string{"zz:lead://x", "://x", "1a://x", "x y://z"} {
		set, _ := template.New(map[string][]byte{"x": []byte(`{"name": "x", "predicate": "https://example.org/p",
			"signerRoles": ["` + role + `"], "fields": {"a": {}}}`)}, aliases)
		if _, ok := set.Get("x"); ok {
			t.Errorf("role %q loaded as an absolute IRI", role)
		}
	}
	for _, role := range []string{"https://example.org/r", "urn:x:r", "did:web:example.org", "a+b.c-d://x"} {
		set, _ := template.New(map[string][]byte{"x": []byte(`{"name": "x", "predicate": "https://example.org/p",
			"signerRoles": ["` + role + `"], "fields": {"a": {}}}`)}, aliases)
		if _, ok := set.Get("x"); !ok {
			t.Errorf("role %q refused: %q", role, set.RefusedReason("x"))
		}
	}
}
