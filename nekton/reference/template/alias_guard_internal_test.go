package template

import "testing"

// The load-time refusals make these unreachable through New and LoadAliases; this checks the second
// guard on its own, with an alias map New would refuse (kton-review on #278).
func TestGuardsBehindTheLoadRefusals(t *testing.T) {
	s := Set{
		templates: map[string]Template{
			"deviation": {Name: "deviation", Predicate: "urn:qm:deviation"},
			"other":     {Name: "other", Predicate: "urn:qm:other"},
		},
		aliases: aliasFile{
			Templates: map[string]string{"deviation": "other"},
			Prefixes:  map[string]string{"urn": "https://x/", "URN": "https://x/"},
			Terms:     map[string]string{"urn:qm:other": "urn:qm:x"},
		},
	}
	if tm, ok := s.Get("deviation"); !ok || tm.Predicate != "urn:qm:deviation" {
		t.Errorf("Get(deviation) = %q, want the template named deviation", tm.Predicate)
	}
	for _, x := range []string{"urn:qm:other", "URN:qm:a", "tag:x.org,2026:a", "https://x/a", "did:web:x", "mailto:a@b"} {
		if r := s.Resolve(x); r != x {
			t.Errorf("Resolve(%s) = %s, want it unchanged", x, r)
		}
	}
}
