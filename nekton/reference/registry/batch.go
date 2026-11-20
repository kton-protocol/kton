package registry

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"kton.dev/plankton/core"
)

// Adding many claims at once (kton-cockpit 20.11.: a batch say of 16,600 claims).
//
// Add, called N times, re-reads two files per claim under the write lock: the claim's scope file, to
// union an earlier line of the same claim (a co-signature written by another process), and the .seq
// position map, which it then rewrites whole. Both are the right thing for one claim from one of
// several processes, and quadratic for a batch.
//
// AddAll runs the same Add for every envelope - every check, twin union, deferral and position rule
// is Add's own - but takes the write lock ONCE for the batch. Holding it, nothing else writes the
// store, so what the batch read is still what is on disk: each scope file is read once and kept in
// memory as it is appended to, and the position map is read once and written once at the end.
//
// The result on disk is what N Adds would leave: the same lines in the same order, the same
// positions. If the process dies mid-batch, the lines appended so far are on disk without positions;
// that is the state a git merge leaves, a full Open numbers them, and OpenForWrite asks for one.

// AddResult is what Add returned for one envelope of a batch.
type AddResult struct {
	ID    string
	IsNew bool
	Err   error // the envelope was refused; the batch went on
}

type batchState struct {
	lockPath string
	touched  time.Time
	seq      core.SeqMap
	dirty    bool
	lines    map[string][]objectFile // scope file -> its lines, as read once and appended since
}

// AddAll adds envs in order, as Add would one by one, under one write lock. An envelope Add refuses is
// reported in its result and the batch goes on; a failure to write the store stops it, and the
// positions issued so far are still written.
func (r *Registry) AddAll(envs []core.Envelope) (results []AddResult, err error) {
	if r.batch != nil {
		return nil, os.ErrInvalid // no nested batches
	}
	lp := filepath.Join(r.dir, ".objects.lock")
	err = withLockFile(lp, func() (ferr error) {
		b := &batchState{lockPath: lp, touched: time.Now(), lines: map[string][]objectFile{},
			seq: core.ReadSeqMap(filepath.Join(r.dir, seqFileName))}
		r.batch = b
		r.epoch = b.seq.Epoch
		defer func() {
			r.batch = nil
			if b.dirty {
				if werr := core.WriteSeqMap(filepath.Join(r.dir, seqFileName), b.seq); werr != nil && ferr == nil {
					ferr = werr
				}
			}
		}()
		for _, env := range envs {
			id, isNew, aerr := r.Add(env)
			if aerr != nil && isPersistErr(aerr) {
				return aerr
			}
			results = append(results, AddResult{ID: id, IsNew: isNew, Err: aerr})
		}
		return nil
	})
	return results, err
}

// assign issues positions from the batch's map, as resolveSeqs does from the file.
func (b *batchState) assign(r *Registry, ids []string) map[string]int {
	r.epoch = b.seq.Epoch
	if b.seq.Assign(ids) {
		b.dirty = true
	}
	return b.seq.Seq
}

// locked runs fn under the lock the batch already holds. The lock's age is what lets another process
// steal a lock from a crashed holder (30 s), so a long batch keeps it fresh.
func (b *batchState) locked(fn func() error) error {
	if now := time.Now(); now.Sub(b.touched) > 5*time.Second {
		_ = os.Chtimes(b.lockPath, now, now)
		b.touched = now
	}
	return fn()
}

// linesFor returns the lines of a scope file that can carry claim id: from the batch's copy of the
// file while a batch runs, from the file otherwise.
func (r *Registry) linesFor(path, id string) []objectFile {
	if r.batch == nil {
		return readSubnektonFor(path, id)
	}
	all, ok := r.batch.lines[path]
	if !ok {
		all = readSubnekton(path)
		r.batch.lines[path] = all
	}
	var out []objectFile
	for _, of := range all {
		if of.ClaimID == id {
			out = append(out, of)
		}
	}
	return out
}

// appendLine appends a line to a scope file and, in a batch, to the batch's copy of it.
func (r *Registry) appendLine(path string, of objectFile) error {
	if err := appendSubnekton(path, of); err != nil {
		return err
	}
	if r.batch != nil {
		if _, ok := r.batch.lines[path]; ok {
			r.batch.lines[path] = append(r.batch.lines[path], of)
		}
	}
	return nil
}

// isPersistErr: the store could not be written, or a write registry needs a full Open - either way
// the rest of the batch cannot be added as Add would add it.
func isPersistErr(err error) bool {
	return errors.Is(err, ErrPersist) || errors.Is(err, ErrNeedsFullOpen)
}
