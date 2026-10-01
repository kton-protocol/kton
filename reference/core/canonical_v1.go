package core

import (
	"encoding/json"
	"fmt"
	"sort"
)

// CheckCanonicalForm enforces the foton/v1 wire rules (SPEC §6.6.1) on a statement. A v0 statement
// passes unchecked: its form is what it always was.
//
// The rules exist so that a v1 payload is a FUNCTION of the record's identity. v0 lets a producer
// vary three things the id does not cover - the order of inputs and subjects, `uri`, and
// `specVersion` - and every variation is a different signed payload for the same foton. Signatures
// never union across differing payloads (registry), so two producers of the same work could not
// co-sign it. v1 removes all three: anything left that differs between two honest producers is a
// difference in the work.
func (st *Statement) CheckCanonicalForm() error {
	if st.PredicateType != PredicateFotonV1 {
		return nil
	}
	if err := canonicalSubjects("subject", st.Subject); err != nil {
		return err
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return fmt.Errorf("foton/v1 predicate: %w", err)
	}
	for k := range p {
		if k != "inputs" && k != "protocol" {
			return fmt.Errorf("foton/v1 predicate carries %q; a v1 predicate holds only inputs and protocol "+
				"(anything else would differ between producers of the same work)", k)
		}
	}
	var ins []Subject
	if raw, ok := p["inputs"]; ok {
		if err := json.Unmarshal(raw, &ins); err != nil {
			return fmt.Errorf("foton/v1 inputs: %w", err)
		}
	}
	return canonicalSubjects("input", ins)
}

func canonicalSubjects(kind string, subs []Subject) error {
	for i, s := range subs {
		if len(s.URI) > 0 {
			return fmt.Errorf("foton/v1 %s %q carries uri; v1 locators travel as material (scheme %s), not in the signed record",
				kind, s.Name, "kton-locator/v1")
		}
		if i > 0 && !subjectLess(subs[i-1], s) {
			return fmt.Errorf("foton/v1 %ss are not in canonical order (by path, then digest): %q before %q",
				kind, subs[i-1].Name, s.Name)
		}
	}
	return nil
}

func subjectLess(a, b Subject) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Digest["sha256"] < b.Digest["sha256"]
}

// SortRefs orders FileRefs canonically - by path, then by hash - as foton/v1 lists them. The order
// is a property of the wire form, not of identity: FotonID itself still hashes the list it is given.
func SortRefs(refs []FileRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Path != refs[j].Path {
			return refs[i].Path < refs[j].Path
		}
		return refs[i].Hash < refs[j].Hash
	})
}
