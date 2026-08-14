package main

// scope.go is the browser SCOPE side: the §7.4 chain grammar - membership, order, heads, and the
// gap check a seal is judged by - computed from a set of envelopes and a scope id.
//
// It exists so a browser cockpit does not reimplement the chain rules in JavaScript. `nekton head`
// can already do this natively, and a page cannot call a binary; without this surface every cockpit
// grows its own walk of `prev`, and those walks disagree. Same reason the SigningInput/Seal split
// exists on the authoring side.
//
// Two §7.4 properties drive the shape of the output:
//
//   - **Ingest is monotone.** A well-formed scoped statement is accepted even when its `prev` does
//     not resolve - the missing link may live in another source (Clause 11). So an unresolved `prev`
//     is REPORTED, never an error, and never conflated with a malformed one. Incomplete is not
//     invalid.
//   - **The no-gap rule is a seal-verification judgment**, evaluated over the resolved union when a
//     seal is relied upon - not an ingest rejection. Hence `verdict`, computed per head, over
//     whatever set of envelopes the caller passed in.
//
// What a seal over a branched scope *means* is deliberately not answered here: SPEC §7.4 leaves
// sealing rules to consumers. This reports the structure and the mechanical consequence of it - a
// head commits to its own path and to nothing on a sibling branch - and prescribes no remedy.
//
// It says nothing about AUTHENTICITY: membership here is structural. Use BuildGraph for the
// signature verification pass.
//
// No build tag: this file compiles natively too, so `go test` exercises the exact code the browser
// runs.

import (
	"encoding/json"
	"fmt"
	"sort"

	"kton.dev/nekton/claim"
)

// scopeMember is one claim that names the scope.
type scopeMember struct {
	ID        string `json:"id"`
	Prev      string `json:"prev,omitempty"`
	By        string `json:"by,omitempty"`
	When      string `json:"when,omitempty"`
	Predicate string `json:"predicate,omitempty"`
	Depth     int    `json:"depth"` // links from the seed; -1 when it does not reach the seed
}

// scopeHead is a tip of the chain: an in-scope claim that no other in-scope claim names as prev.
// Path is the ordered chain it commits to, seed first. A linear scope has exactly one head; a
// branched scope has several, which is a legal state.
type scopeHead struct {
	ID          string   `json:"id"`
	ReachesSeed bool     `json:"reachesSeed"`
	Path        []string `json:"path"`
	// Gap is the first `prev` on this path that the passed-in envelopes do not resolve, if any.
	// Its presence is what makes ReachesSeed false, and it is a resolution fact, not a verdict of
	// invalidity - another source may carry the missing claim.
	Gap string `json:"gap,omitempty"`
}

// scopeDefect is a §7.4 grammar violation. Unlike a gap, this is intrinsic to the claim: no
// additional source can repair it.
type scopeDefect struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type scopeVerdict struct {
	// Sealable is the §7.4 no-gap judgment over the envelopes given: the seed is present, every head
	// reaches it, and no member is malformed. False does NOT mean invalid - read Gaps first.
	Sealable bool   `json:"sealable"`
	Branched bool   `json:"branched"`
	Note     string `json:"note"`
}

type scopeView struct {
	Scope       string        `json:"scope"`
	SeedPresent bool          `json:"seedPresent"`
	ChainLen    int           `json:"chainLen"`
	Members     []scopeMember `json:"members"`
	Heads       []scopeHead   `json:"heads"`
	Defects     []scopeDefect `json:"defects"`
	Verdict     scopeVerdict  `json:"verdict"`
}

// BuildScope reads the §7.4 chain of one scope out of a union of records and returns it as JSON:
// the members in order, the head(s), the unresolved links, the grammar defects, and the no-gap
// verdict. unionJSON is the same {fotonId|claimId, envelope} array BuildGraph takes; non-claim and
// out-of-scope records are ignored.
func BuildScope(unionJSON, scopeID string) (string, error) {
	if scopeID == "" {
		return "", fmt.Errorf("BuildScope needs a scope id")
	}
	var recs []record
	if err := json.Unmarshal([]byte(unionJSON), &recs); err != nil {
		return "", err
	}

	view := scopeView{Scope: scopeID, Members: []scopeMember{}, Heads: []scopeHead{}, Defects: []scopeDefect{}}
	members := map[string]*scopeMember{}

	for _, r := range recs {
		st, payload, err := claim.ParseEnvelope(r.Envelope)
		if err != nil {
			continue // not a claim envelope, or a non-canonical payload: not this function's business
		}
		// SECURITY: re-derive the id from the envelope; never trust the declared claimId in the union.
		// A planted record whose stored id equals a real member's would otherwise be able to insert
		// itself into the chain or shadow a head (the sibling of the graph.go id-trust finding).
		id := claim.ClaimID(payload)

		if st.IsSeed() {
			if id == scopeID {
				view.SeedPresent = true
			}
			continue // a seed is never a member of its own scope
		}
		p, err := st.ParsePredicate()
		if err != nil || p == nil || p.Scope != scopeID {
			continue
		}
		if _, dup := members[id]; dup {
			continue // same claim from two sources: one member (set-union dedup by id)
		}
		m := &scopeMember{ID: id, Prev: p.Prev, By: p.By, When: p.When, Predicate: p.Predicate.Key(), Depth: -1}
		members[id] = m

		// §7.4 grammar, checked here because no later source can fix either of these.
		if p.Prev == "" {
			view.Defects = append(view.Defects, scopeDefect{id, "scoped claim carries no prev (SPEC 7.4 requires one on every non-genesis statement)"})
		}
		if p.Genesis {
			view.Defects = append(view.Defects, scopeDefect{id, "genesis:true on a non-seed statement (SPEC 7.4 admits it only on a scope/v0 seed)"})
		}
	}
	view.ChainLen = len(members)

	// Heads: in-scope claims that nothing in-scope names as prev.
	referenced := map[string]bool{}
	for _, m := range members {
		if m.Prev != "" {
			referenced[m.Prev] = true
		}
	}
	var headIDs []string
	for id := range members {
		if !referenced[id] {
			headIDs = append(headIDs, id)
		}
	}
	sort.Strings(headIDs)
	if len(members) == 0 {
		// An empty scope's tip is the seed itself - the same answer `nekton head` gives, so a page and
		// the CLI agree on a scope that has been opened but not yet written to.
		headIDs = []string{scopeID}
	}

	for _, h := range headIDs {
		head := scopeHead{ID: h, Path: []string{}}
		if len(members) == 0 {
			head.ReachesSeed = view.SeedPresent
			head.Path = []string{scopeID}
			if !view.SeedPresent {
				head.Gap = scopeID
			}
			view.Heads = append(view.Heads, head)
			continue
		}
		// Walk prev links back toward the seed. A cycle cannot occur among honest claims - a claim id
		// covers its prev, so a loop would require a hash preimage - but the walk is bounded anyway:
		// this input is attacker-supplied, and a hang in a browser tab is a real denial of service.
		var rev []string
		seen := map[string]bool{}
		cur := h
		for {
			if seen[cur] {
				head.Gap = cur
				break
			}
			seen[cur] = true
			rev = append(rev, cur)
			m := members[cur]
			if m == nil || m.Prev == "" {
				head.Gap = cur // malformed member: already reported in Defects
				break
			}
			if m.Prev == scopeID { // reached the seed
				head.ReachesSeed = view.SeedPresent
				if !view.SeedPresent {
					head.Gap = scopeID
				}
				break
			}
			if _, ok := members[m.Prev]; !ok {
				head.Gap = m.Prev // unresolved: may live in another source (Clause 11)
				break
			}
			cur = m.Prev
		}
		// Path reads seed-first: the order the chain was written.
		if head.ReachesSeed {
			head.Path = append(head.Path, scopeID)
		}
		for i := len(rev) - 1; i >= 0; i-- {
			head.Path = append(head.Path, rev[i])
		}
		if head.ReachesSeed {
			for i, id := range head.Path {
				if m := members[id]; m != nil {
					m.Depth = i // the seed sits at 0, so the first claim is at depth 1
				}
			}
		}
		view.Heads = append(view.Heads, head)
	}

	// Members ordered by position in the chain, then by id so a branched scope still reads
	// deterministically and two readers of the same union produce the same view.
	for _, m := range members {
		view.Members = append(view.Members, *m)
	}
	sort.Slice(view.Members, func(i, j int) bool {
		a, b := view.Members[i], view.Members[j]
		if a.Depth != b.Depth {
			if a.Depth < 0 { // unplaced members sort last, not first
				return false
			}
			if b.Depth < 0 {
				return true
			}
			return a.Depth < b.Depth
		}
		return a.ID < b.ID
	})
	sort.Slice(view.Defects, func(i, j int) bool { return view.Defects[i].ID < view.Defects[j].ID })

	view.Verdict = verdictFor(&view)
	out, err := json.Marshal(view)
	return string(out), err
}

// verdictFor renders the §7.4 judgment in the terms the clause itself uses, keeping the two failure
// modes apart: a GAP is a resolution fact that another source can repair, a DEFECT never is.
func verdictFor(v *scopeView) scopeVerdict {
	gaps := 0
	for _, h := range v.Heads {
		if h.Gap != "" {
			gaps++
		}
	}
	vd := scopeVerdict{Branched: len(v.Heads) > 1}
	switch {
	case !v.SeedPresent:
		vd.Note = "the seed for this scope is not among the records given; membership and order cannot be judged from here (SPEC 7.4: incomplete, not invalid - resolve more sources)"
	case len(v.Defects) > 0:
		vd.Note = fmt.Sprintf("%d claim(s) violate the 7.4 chain grammar; no further source can repair this", len(v.Defects))
	case gaps > 0:
		vd.Note = fmt.Sprintf("%d of %d head(s) do not reach the seed from these records; the missing links may live in another source (SPEC 7.4, Clause 11) - incomplete, not invalid", gaps, len(v.Heads))
	default:
		vd.Sealable = true
		vd.Note = fmt.Sprintf("every head reaches the seed without a gap over the %d record(s) resolved here", v.ChainLen)
		if vd.Branched {
			vd.Note += "; the scope is branched, and each head commits only to the claims on its own path"
		}
	}
	return vd
}
