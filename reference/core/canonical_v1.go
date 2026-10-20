package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	// The ref is part of the action key and the id, so it has exactly one spelling: sha256: and 64
	// lowercase hex. A bare ref (no descriptor to recompute it from) was taken as written, so
	// "sha256:aaa…" and "sha256:AAA…" were two computations, and "not-a-hash" was admitted.
	var proto struct {
		Ref string `json:"ref"`
	}
	if raw, ok := p["protocol"]; ok {
		if err := json.Unmarshal(raw, &proto); err != nil {
			return fmt.Errorf("foton/v1 protocol: %w", err)
		}
	}
	if norm, ok := NormalizeContentHash(proto.Ref); !ok || norm != proto.Ref {
		return fmt.Errorf("foton/v1 protocol.ref %q is not sha256: followed by 64 lowercase hex", proto.Ref)
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
		// One file per path. Inputs already refuse a second hash under one path (the action key);
		// outputs did not, so one record could claim two different files at the same place.
		if i > 0 && subs[i-1].Name == s.Name {
			return fmt.Errorf("foton/v1 lists %s path %q twice; each path names one file", kind, s.Name)
		}
		if i > 0 && !subjectLess(subs[i-1], s) {
			return fmt.Errorf("foton/v1 %ss are not in canonical order (by path, then digest): %q before %q",
				kind, subs[i-1].Name, s.Name)
		}
	}
	return nil
}

// subjectLess orders by name, then by digest, comparing the BYTES of the UTF-8 encoding (Go's string
// <). Not UTF-16 code units as JCS orders object keys (§5): the two disagree for names outside the
// BMP, and SPEC §6.6.1 names the byte order.
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

// CanonicalV1Payload is THE foton/v1 statement of a record: the one byte string a v1 payload for this
// foton may be. Authoring signs exactly these bytes (foton.StatementPayload), and ingest admits a v1
// payload only if it equals them (CheckV1Payload).
//
// The listed rules (order, no uri, no specVersion) are not enough on their own. Anything else a
// producer's tool may vary - whitespace, key order, hex case, a second digest algorithm, an extra
// member in a subject, the protocol or the statement - also yields a different payload for the same
// id, signatures never union across payloads, and the first one ingested would keep every honest
// co-signer out. A member this kernel does not know is refused the same way, so a later field can
// never be dropped silently and merged into a record that does not carry it.
//
// The protocol carries its descriptor only when there is one (never `"descriptor": null`), and its
// ref as stated: when a descriptor is present, the record's own ref check (FotonID) already ties
// the two together.
func CanonicalV1Payload(f *Foton) ([]byte, error) {
	subjects := func(refs []FileRef) []any {
		sorted := append([]FileRef(nil), refs...)
		SortRefs(sorted)
		out := make([]any, 0, len(sorted))
		for _, r := range sorted {
			s := map[string]any{"name": r.Path}
			// An unbound slot of a potential (§6.4) has no hash, and its subject no digest: not an
			// empty one, which would read as a content address that is not there.
			if r.Hash != "" {
				s["digest"] = map[string]any{"sha256": strings.TrimPrefix(r.Hash, "sha256:")}
			}
			out = append(out, s)
		}
		return out
	}
	protocol := map[string]any{"kind": f.Protocol.Kind, "ref": f.Protocol.Ref}
	if f.Protocol.Descriptor != nil {
		protocol["descriptor"] = f.Protocol.Descriptor
	}
	if c := f.Protocol.coveredConditions(); c != nil {
		protocol["conditions"] = c
	}
	return CanonValue(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjects(f.Outputs),
		"predicateType": PredicateFotonV1,
		"predicate": map[string]any{
			"inputs":   subjects(f.Inputs),
			"protocol": protocol,
		},
	})
}

// CheckV1Payload refuses a foton/v1 payload that is not byte-identical to the canonical statement of
// the record it carries (SPEC §6.6.1). f is the record parsed from payload.
func CheckV1Payload(payload []byte, f *Foton) error {
	want, err := CanonicalV1Payload(f)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, want) {
		return fmt.Errorf("foton/v1 payload is not the canonical statement of its record; a v1 payload " +
			"MUST be byte-identical to it (SPEC §6.6.1), or two producers of the same work could not co-sign")
	}
	return nil
}
