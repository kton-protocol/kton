package template_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/template"
)

const typedTemplate = `{
  "name": "qm/state",
  "predicate": "qm:state",
  "fields": {
    "revision": {"type": "integer"},
    "lifecycleState": {"type": "iri"}
  }
}`

const aliases = `{"prefixes": {"qm": "https://qm.example/v/"}}`

func typedSet(t *testing.T, extra map[string][]byte) template.Set {
	t.Helper()
	tpls := map[string][]byte{"qm/state": []byte(typedTemplate)}
	for k, v := range extra {
		tpls[k] = v
	}
	set, err := template.New(tpls, []byte(aliases))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestIntegerField(t *testing.T) {
	set := typedSet(t, nil)
	for _, ok := range []string{"0", "42", "-7", "+3", "0012"} {
		if _, err := set.Spec("qm/state", "urn:doc:1", map[string]string{"revision": ok}, nil); err != nil {
			t.Errorf("revision %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"4.2", "x", "+", "1e3", " 4", "4 "} {
		if _, err := set.Spec("qm/state", "urn:doc:1", map[string]string{"revision": bad}, nil); err == nil {
			t.Errorf("revision %q accepted", bad)
		}
	}
}

func TestIRIField(t *testing.T) {
	set := typedSet(t, nil)
	for in, want := range map[string]string{
		"qm:Approved":                   "https://qm.example/v/Approved", // resolved CURIE is signed
		"https://qm.example/v/Approved": "https://qm.example/v/Approved",
		"urn:qm:state:approved":         "urn:qm:state:approved",
		"did:key:z6Mk":                  "did:key:z6Mk",
	} {
		spec, err := set.Spec("qm/state", "urn:doc:1", map[string]string{"lifecycleState": in}, nil)
		if err != nil {
			t.Errorf("%q refused: %v", in, err)
			continue
		}
		if got := spec.Object["lifecycleState"]; got != want {
			t.Errorf("%q signed as %v, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"Approved", "xx:Approved", "Note: foo", "https://a b", "urn:", "1x://y"} {
		if _, err := set.Spec("qm/state", "urn:doc:1", map[string]string{"lifecycleState": bad}, nil); err == nil {
			t.Errorf("%q accepted as an IRI", bad)
		}
	}
}

// A template with a type the kernel does not know is refused, named, and the others still work.
func TestUnknownFieldTypeRefusesThatTemplate(t *testing.T) {
	set := typedSet(t, map[string][]byte{
		"qm/typo": []byte(`{"name": "qm/typo", "predicate": "qm:x", "fields": {"n": {"type": "int"}}}`),
	})
	if _, ok := set.Get("qm/typo"); ok {
		t.Fatal("a template with type int loaded")
	}
	if !strings.Contains(set.Refused()["qm/typo"], `"int"`) {
		t.Errorf("Refused() = %v, want qm/typo named with its type", set.Refused())
	}
	_, err := set.Spec("qm/typo", "urn:doc:1", map[string]string{"n": "1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("Spec on a refused template: %v, want the reason", err)
	}
	if _, err := set.Spec("qm/state", "urn:doc:1", map[string]string{"revision": "1"}, nil); err != nil {
		t.Errorf("the other template stopped working: %v", err)
	}
}
