package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// SeqMap is a store's LOCAL federation numbering: record id -> the position a peer's cursor
// compares against (SPEC §12, `sync(since)`).
//
// It is stored BESIDE the records - in the registry root, next to peers.json - and never inside
// them. Two reasons, and both are load-bearing:
//
//   - A record's on-disk bytes stay identical on every peer, which is what makes a git merge of two
//     registries conflict-free. Numbering a record in place would make the same logical record
//     differ per store and turn every merge into a conflict.
//   - The number IS local. Two stores that hold the same records in a different order legitimately
//     number them differently; a cursor is only ever meaningful against the store that issued it.
//
// The invariant the numbering must hold is narrow but absolute: ONCE ISSUED, A POSITION NEVER
// CHANGES, and a newly-seen record always sorts above every position already issued. Before this
// existed, a record's position was its rank in the hash-sorted store, so planting a record whose
// hash sorts EARLY shifted every later record's position down by one - and a record a peer had
// already seen fell back to or below the cursor that peer had stored, never to be delivered again.
// Two hash attempts were enough to hide a record from a peer permanently (AUD-02).
type SeqMap struct {
	Next int            `json:"next"` // the next position to hand out; only ever grows
	Seq  map[string]int `json:"seq"`  // record id -> position
}

// ReadSeqMap loads the numbering. A missing, empty or unparseable file reads as an EMPTY map, not
// an error: the numbering is derived local state, so the worst case is that positions are reissued
// and peers re-sync from the start - noisy, never wrong. Refusing to open the store instead would
// turn one bad byte in local bookkeeping into a total outage.
func ReadSeqMap(path string) SeqMap {
	m := SeqMap{Seq: map[string]int{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var on SeqMap
	if json.Unmarshal(b, &on) != nil || on.Seq == nil {
		return m
	}
	for _, n := range on.Seq {
		if n >= on.Next {
			on.Next = n + 1 // a truncated/edited file must not reissue a live position
		}
	}
	if on.Next < 1 {
		on.Next = 1
	}
	return on
}

// Assign gives every id that has no position yet the next one, in the order given. Callers pass ids
// in a STABLE store order so that a numbering derived twice from the same store agrees. Ids that
// already have a position keep it - that is the whole point. Returns whether anything was added.
func (m *SeqMap) Assign(ids []string) bool {
	if m.Seq == nil {
		m.Seq = map[string]int{}
	}
	if m.Next < 1 {
		m.Next = 1
	}
	changed := false
	for _, id := range ids {
		if _, ok := m.Seq[id]; ok || id == "" {
			continue
		}
		m.Seq[id] = m.Next
		m.Next++
		changed = true
	}
	return changed
}

// WriteSeqMap persists the numbering atomically (temp + rename), sorted so the file is stable in a
// diff. Callers hold the store's write lock.
func WriteSeqMap(path string, m SeqMap) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// json.Marshal already sorts map keys; sorting here is only to keep the type explicit about it.
	ids := make([]string, 0, len(m.Seq))
	for id := range m.Seq {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
