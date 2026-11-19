package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"kton.dev/nekton/claim"
)

// The root nekton (#213, SPEC §7.4). A store's root is an ordinary scope: a normal seed, signed by
// whoever created the store, under which every claim this store writes without naming a scope is
// chained, and in which every subnekton this store opens is registered. That turns the root from a
// bag into an ordered, gap-evident list: a claim removed or reordered between two linked entries
// leaves a dangling prev, exactly as in any scope.
//
// What the store keeps is local state, not protocol: which of the seeds it holds is ITS root (once
// it has mirrored others, their roots look like any scope), and the head it chains from. Both live
// in rootMarker next to .format. Where a backend keeps them is the backend's business; the protocol
// only says a store knows its own root.
const rootMarker = ".root"

// RegistersPredicate is the predicate of the root entry that registers a subnekton this store
// opened: subject = the child seed's id. vocabulary: nk:registers.
const RegistersPredicate = "https://kton.dev/v/registers"

type rootState struct {
	Root string `json:"root"`
	Head string `json:"head"`
}

func readRoot(objectsDir string) (rootState, error) {
	var rs rootState
	b, err := readFileShared(filepath.Join(objectsDir, rootMarker))
	if err != nil {
		if os.IsNotExist(err) {
			return rs, nil
		}
		return rs, err
	}
	if err := json.Unmarshal(b, &rs); err != nil || rs.Root == "" {
		return rootState{}, fmt.Errorf("nekton root marker %s is not readable (%q); refusing to guess "+
			"which scope is this store's root", filepath.Join(objectsDir, rootMarker), string(b))
	}
	return rs, nil
}

func (r *Registry) writeRoot() error {
	b, err := json.Marshal(r.root)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.objectsDir, rootMarker), append(b, '\n'))
}

// Root returns this store's own root scope id, or "" if it has none yet.
func (r *Registry) Root() string { return r.root.Root }

// RootHead returns the root entry this store chains its next unscoped claim from: the entry it
// appended last, or the root seed itself while the chain is empty. "" if there is no root.
func (r *Registry) RootHead() string {
	if r.root.Head != "" {
		return r.root.Head
	}
	return r.root.Root
}

// SetRoot records id as this store's root, continuing from head: a root entry of the chain (or "" for
// the only head there is). id must be a seed this store holds, and the store must not have another
// root: a store has one root for its whole life. It is called on the caller's own write path only
// (nekton init, or adopting a copy), never on mirror, sync or ingest - a kernel does not decide on
// ingest.
//
// A store that adopts a root it already holds entries of (a clone, a restored copy) continues from
// the chain's tip, not from the seed: starting at the seed would fork its own history. If the root is
// already forked there is no one tip; SetRoot then refuses and names the heads, and the caller says
// which branch is this store's (#259 review R4).
func (r *Registry) SetRoot(id, head string) error {
	if r.root.Root != "" && r.root.Root != id {
		return fmt.Errorf("this store already has a root (%s); a store keeps one root", r.root.Root)
	}
	if !r.seeds[id] {
		return fmt.Errorf("%s is not a seed this store holds, so it cannot be its root", id)
	}
	heads, n, _ := r.Heads(id)
	switch {
	case head != "":
		if head != id && !r.inScope[id][head] {
			return fmt.Errorf("%s is not an entry of root %s", head, id)
		}
	case n > 0 && len(heads) > 1:
		return fmt.Errorf("root %s is forked (heads %v): say which one this store continues from", id, heads)
	case n > 0:
		head = heads[0]
	}
	if head == id {
		head = ""
	}
	r.root = rootState{Root: id, Head: head}
	return r.writeRoot()
}

// ownAppend moves the local head to id when id is a root entry that names the current head as its
// prev. It is called on this store's own write path only (Write, RegisterSubnekton), never from Add:
// an entry that arrives by add or mirror - from a copy of this store, or signed by anyone - must not
// become the point this store continues from (#259 review R1). Such an entry is a fork or off-chain,
// and reported as that.
func (r *Registry) ownAppend(id string) {
	if r.root.Root == "" {
		return
	}
	rec, ok := r.claimByID[id]
	if !ok {
		return
	}
	st, _, err := claim.ParseEnvelope(rec.Envelope)
	if err != nil || st.IsSeed() {
		return
	}
	p, err := st.ParsePredicate()
	if err != nil || p == nil || p.Scope != r.root.Root || p.Prev != r.RootHead() {
		return
	}
	r.root.Head = id
	if err := r.writeRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the root head %s: %v\n", id, err)
	}
}

// Chain is this store's own root chain: the entries from the root seed to the local head, oldest
// first, following prev. Only these are what this store said and opened (#259 review R3): anyone can
// sign an entry naming a root, and a copy of the store writes its own, but none of those is on the
// path from this store's head, because the head moves only on this store's own writes.
func (r *Registry) Chain() []string {
	if r.root.Root == "" {
		return nil
	}
	var back []string
	seen := map[string]bool{}
	for cur := r.RootHead(); cur != r.root.Root && cur != "" && !seen[cur]; {
		seen[cur] = true
		rec, ok := r.claimByID[cur]
		if !ok {
			break // a missing middle: Unresolved reports it
		}
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			break
		}
		p, err := st.ParsePredicate()
		if err != nil || p == nil {
			break
		}
		back = append(back, cur)
		cur = p.Prev
	}
	for i, j := 0, len(back)-1; i < j; i, j = i+1, j-1 {
		back[i], back[j] = back[j], back[i]
	}
	return back
}

// OffChain returns the entries that name this store's root but are not on its own chain: forks from a
// copy of the store, or entries anyone signed (sorted). They are reported, never counted as this
// store's (SPEC §7.4).
func (r *Registry) OffChain() []string {
	if r.root.Root == "" {
		return nil
	}
	on := map[string]bool{}
	for _, id := range r.Chain() {
		on[id] = true
	}
	var out []string
	for id := range r.inScope[r.root.Root] {
		if !on[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Forks returns, for one scope, every point that more than one in-scope claim names as its prev,
// with those claims (sorted). A fork is a fact to report, not invalidity: it happens when a store is
// cloned and both copies keep writing.
func (r *Registry) Forks(scope string) map[string][]string {
	children := map[string][]string{}
	for id := range r.inScope[scope] {
		rec, ok := r.claimByID[id]
		if !ok {
			continue
		}
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		p, err := st.ParsePredicate()
		if err != nil || p == nil || p.Prev == "" {
			continue
		}
		children[p.Prev] = append(children[p.Prev], id)
	}
	forks := map[string][]string{}
	for prev, ids := range children {
		if len(ids) > 1 {
			sort.Strings(ids)
			forks[prev] = ids
		}
	}
	return forks
}

// Registered returns the subnekton seed ids this store's root registers (RegistersPredicate entries
// on its own Chain - not every registers entry anyone filed under the root, #259 review R3), each with
// whether the seed itself is present.
func (r *Registry) Registered() map[string]bool {
	out := map[string]bool{}
	if r.root.Root == "" {
		return out
	}
	for _, id := range r.Chain() {
		rec, ok := r.claimByID[id]
		if !ok {
			continue
		}
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil || len(st.Subject) == 0 {
			continue
		}
		p, err := st.ParsePredicate()
		if err != nil || p == nil || p.Predicate.URI != RegistersPredicate {
			continue
		}
		child := st.Subject[0].Key()
		out[child] = r.seeds[child]
	}
	return out
}
