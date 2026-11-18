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

// SetRoot records id as this store's root. id must be a seed this store holds, and the store must not
// have a root already: a store has one root for its whole life, and choosing another would orphan the
// chain it has. It is called on the caller's own write path only (nekton init, or the first write
// that needs a root), never on mirror, sync or ingest - a kernel does not sign or decide on ingest.
func (r *Registry) SetRoot(id string) error {
	if r.root.Root != "" {
		if r.root.Root == id {
			return nil
		}
		return fmt.Errorf("this store already has a root (%s); a store keeps one root", r.root.Root)
	}
	if !r.seeds[id] {
		return fmt.Errorf("%s is not a seed this store holds, so it cannot be its root", id)
	}
	r.root = rootState{Root: id}
	// A store that adopts a root it already holds entries of (a clone, a restored copy) continues
	// from the chain's tip, not from the seed: starting at the seed would fork its own history.
	if heads, n, _ := r.Heads(id); n > 0 && len(heads) == 1 {
		r.root.Head = heads[0]
	}
	return r.writeRoot()
}

// advanceRootHead moves the local head when a newly accepted root entry names the current head as its
// prev. An entry that names an older point (another copy of this store wrote it) does not move the
// head: it is a fork, reported by Forks, and neither branch is invalid (SPEC §11).
func (r *Registry) advanceRootHead(id string, st *claim.Statement) {
	if r.root.Root == "" || st == nil || st.IsSeed() {
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
// in the root scope), sorted, each with whether the seed itself is present.
func (r *Registry) Registered() map[string]bool {
	out := map[string]bool{}
	if r.root.Root == "" {
		return out
	}
	for id := range r.inScope[r.root.Root] {
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
