// Package spectrum checks spectrum fulfilment (SPEC §10) against a registry.
//
// A SPECTRUM defines a tool: the reference fotons (gold-standard model+data -> output) a tool must
// reproduce, plus the normaliser POTENTIAL whose ray defines the comparison. It is structural, not
// semantic - a set of hashes and a potential id - so it belongs in the protocol.
//
// Check is reproducible reasoning: defined inputs (reference and candidate output fotons, the
// potential's ray) give a defined output, re-runnable to the same answer. It RUNS NOTHING: the
// candidate run and the normaliser application are executor jobs done elsewhere; Check only compares
// the resulting fotons by hash. It reports fulfilment, not a verdict - whether that is called "L0" or
// "L1", and whether anyone accepts it as a tool validation, is a signed nekton claim on top.
package spectrum

import (
	"fmt"
	"sort"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// Member is one reference foton of a spectrum, named by its output hash.
type Member struct {
	Name   string `json:"name"`
	Output string `json:"output"`          // reference output hash (sha256:...) - the gold result
	Model  string `json:"model,omitempty"` // optional provenance: the model input (hash or uri)
	Data   string `json:"data,omitempty"`  // optional provenance: the dataset input (hash or uri)
}

// Spectrum is the on-disk manifest. It is content-addressable like any file, so a spectrum can itself
// be pinned, mirrored, or registered as a foton - it is just data that names other data by hash.
type Spectrum struct {
	Spectrum   string   `json:"spectrum"`             // the tool identity, e.g. "nonmem"
	Of         string   `json:"of,omitempty"`         // human label, e.g. "the NONMEM 7.5 estimation tool"
	Normalizer string   `json:"normalizer,omitempty"` // the potential whose ray defines fulfilment (opaque id)
	Members    []Member `json:"members,omitempty"`    // the reference fotons (by output hash)
}

// Status is what Check found for one member.
type Status string

const (
	Identical            Status = "identical"              // the candidate output is the reference output
	Via                  Status = "via"                    // both meet after the spectrum's normalizer
	NoCandidate          Status = "no-candidate"           // the member was not checked
	ReferenceNotRecorded Status = "reference-not-recorded" // no foton in the registry produced the reference
	CandidateNotRecorded Status = "candidate-not-recorded" // no foton in the registry produced the candidate
	// A fulfilment MUST NOT rest on a conditional foton (SPEC §10): one whose re-run need not give the
	// same bytes. These say every recorded producer of that output is conditional. At L0 the candidate
	// hash IS the reference hash, so a reference with an unconditional producer covers the candidate
	// too: candidate-conditional can only arise for a via-normalizer match.
	ReferenceConditional Status = "reference-conditional"
	CandidateConditional Status = "candidate-conditional"
	NotFulfilled         Status = "not-fulfilled" // both recorded, and they do not reproduce
)

// Fulfilled reports whether the status counts toward fulfilment.
func (s Status) Fulfilled() bool { return s == Identical || s == Via }

// MemberResult is one member's line of a Result.
type MemberResult struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
	Candidate string `json:"candidate,omitempty"`
	Status    Status `json:"status"`
}

// Outcome summarises a Result for a gate.
type Outcome string

const (
	OutcomeFulfilled  Outcome = "fulfilled"  // every member fulfilled
	OutcomeIncomplete Outcome = "incomplete" // no member failed, but some had no candidate
	OutcomeFailed     Outcome = "failed"     // at least one checked member was not fulfilled
)

// Result is Check's answer, one entry per member in manifest order.
type Result struct {
	Spectrum   string         `json:"spectrum"`
	Normalizer string         `json:"normalizer,omitempty"`
	Members    []MemberResult `json:"members"`
	Fulfilled  int            `json:"fulfilled"`
	Missing    int            `json:"missing"` // members with no candidate
	// DependsOnConditional lists the conditional fotons in the lineage of any reference or candidate
	// output that was compared. A fulfilment never rests on one directly (the statuses above), but
	// upstream of a pinned input one may still be, and the answer says so (SPEC §11).
	DependsOnConditional []string `json:"dependsOnConditional,omitempty"`
}

// Outcome reports fulfilled, incomplete or failed. A failure outranks an incompleteness.
func (r Result) Outcome() Outcome {
	switch {
	case r.Fulfilled == len(r.Members):
		return OutcomeFulfilled
	case r.Fulfilled+r.Missing == len(r.Members):
		return OutcomeIncomplete
	default:
		return OutcomeFailed
	}
}

// IsContentHash reports whether s is a well-formed "sha256:<64 lowercase hex>" content hash. A member
// or candidate output that is empty or junk would otherwise be accepted, and pure string equality
// would report a spectrum of empty members as fulfilled with nothing ever run.
func IsContentHash(s string) bool {
	n, ok := core.NormalizeContentHash(s)
	return ok && n == s
}

// Check compares candidate outputs (member name -> output hash) against the spectrum's reference
// members in reg. Both the reference and the candidate must be the output of a foton recorded in reg;
// otherwise invented hashes would score as identical. Each must also have a producer that is not
// conditional (SPEC §10), and a normalizer that is conditional is not followed (Registry.
// NormalizedOutput). The comparison is Registry.Reproduces with the
// spectrum's normalizer, the same rule `plankton reproduces` applies.
//
// Check refuses a spectrum without members (a tool defined by zero reference fotons qualifies
// nothing, and 0/0 would pass any gate), a candidate that names no member (a typo read as coverage),
// and a candidate output that is not a content hash.
func Check(reg *registry.Registry, s Spectrum, candidates map[string]string) (Result, error) {
	if len(s.Members) == 0 {
		return Result{}, fmt.Errorf("spectrum %q defines no members; add reference fotons before checking (a memberless spectrum qualifies nothing, SPEC §10)", s.Spectrum)
	}
	member := map[string]bool{}
	names := make([]string, len(s.Members))
	for i, m := range s.Members {
		member[m.Name] = true
		names[i] = m.Name
	}
	given := make([]string, 0, len(candidates))
	for name := range candidates {
		given = append(given, name)
	}
	sort.Strings(given) // the first error reported must not depend on map order
	for _, name := range given {
		if !member[name] {
			return Result{}, fmt.Errorf("candidate %q names no member of spectrum %q; members are: %s", name, s.Spectrum, strings.Join(names, ", "))
		}
		if !IsContentHash(candidates[name]) {
			return Result{}, fmt.Errorf("candidate %q: output must be a sha256:<64hex> content hash, got %q", name, candidates[name])
		}
	}
	if s.Normalizer != "" {
		if f, ok := reg.Foton(s.Normalizer); ok && f.Conditional() {
			return Result{}, fmt.Errorf("spectrum %q names a conditional normalizer %s; a normalization that need not "+
				"give the same bytes twice cannot define fulfilment (SPEC §9, §10)", s.Spectrum, s.Normalizer)
		}
	}
	seen := map[string]bool{}
	res := Result{Spectrum: s.Spectrum, Normalizer: s.Normalizer, Members: make([]MemberResult, 0, len(s.Members))}
	for _, m := range s.Members {
		mr := MemberResult{Name: m.Name, Reference: m.Output}
		c, ok := candidates[m.Name]
		switch {
		case !ok:
			mr.Status = NoCandidate
			res.Missing++
		case len(reg.Producer(m.Output)) == 0:
			mr.Candidate, mr.Status = c, ReferenceNotRecorded
		case len(reg.Producer(c)) == 0:
			mr.Candidate, mr.Status = c, CandidateNotRecorded
		case !reg.HasUnconditionalProducer(m.Output):
			mr.Candidate, mr.Status = c, ReferenceConditional
		case !reg.HasUnconditionalProducer(c):
			mr.Candidate, mr.Status = c, CandidateConditional
		default:
			mr.Candidate, mr.Status = c, NotFulfilled
			rep, err := reg.Reproduces(m.Output, c, s.Normalizer)
			if err != nil {
				return Result{}, fmt.Errorf("member %q: %w", m.Name, err)
			}
			if rep.Matches {
				mr.Status = Identical
				if rep.Level != "L0" {
					mr.Status = Via
				}
			}
		}
		if mr.Status.Fulfilled() {
			res.Fulfilled++
		}
		res.Members = append(res.Members, mr)
		if ok {
			for _, id := range reg.ConditionalIn(append(reg.Lineage(m.Output), reg.Lineage(c)...)) {
				if !seen[id] {
					seen[id] = true
					res.DependsOnConditional = append(res.DependsOnConditional, id)
				}
			}
		}
	}
	return res, nil
}
