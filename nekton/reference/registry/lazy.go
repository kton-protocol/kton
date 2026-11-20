package registry

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// Appending without opening the whole store (#248).
//
// Writing one claim used to Open the registry first - read, parse and index every subnekton and settle
// every chain - and only then Add one line: about 1 s at 1k claims, 72-126 s at 100k. Everything Add
// needs for one claim is in that claim's own scope file: its twin (the scope is part of the signed
// payload, so one claim id lives in exactly one file), the scope's seed (a seed's file is its own
// scope's), and its prev (same scope). A write registry therefore loads a scope file the first time a
// claim of that scope is added, and nothing else.
//
// The result on disk is identical to a full Open + Add. Positions come from the .seq file under the
// write lock either way. The one thing a partial load could do differently is number records that are
// on disk WITHOUT a position yet (a merge nobody has opened since): a full Open numbers those in store
// order across every file. A write registry that meets one refuses with ErrNeedsFullOpen, and the
// caller writes through a full Open instead - WriteTo does that.

// ErrNeedsFullOpen says a write registry met something only a full Open handles identically.
var ErrNeedsFullOpen = errors.New("this write needs the store opened whole")

// OpenForWrite opens a store for adding claims without reading it whole. Only the scope files of the
// claims added are loaded, so its read methods (About, Heads, Records, ...) see only those: use it to
// write, and Open to read.
func OpenForWrite(dir string) (*Registry, error) {
	r := newRegistry(dir)
	if err := os.MkdirAll(r.objectsDir, 0o755); err != nil {
		return nil, err
	}
	if err := checkStoreFormat(dir, r.objectsDir); err != nil {
		return nil, err
	}
	// The 0.2 per-claim layout is refused here as Open refuses it, before anything is written: a
	// write registry never runs readStore, and writing into such a store left one every reader
	// refuses while the writer reported success (#263 + #269 review D1).
	if err := refuseLegacyLayout(r.objectsDir); err != nil {
		return nil, err
	}
	if err := writeStoreFormat(r.objectsDir); err != nil {
		return nil, err
	}
	var err error
	if r.root, err = readRoot(r.objectsDir); err != nil {
		return nil, err
	}
	r.epoch = core.ReadSeqMap(filepath.Join(dir, seqFileName)).Epoch
	r.lazy = true
	r.loaded = map[string]bool{}
	return r, nil
}

// loadScope reads one scope's file into a write registry, once.
func (r *Registry) loadScope(scope string) error {
	path, err := subnektonPath(r.objectsDir, scope)
	if err != nil {
		return err
	}
	if r.loaded[path] {
		return nil
	}
	r.loaded[path] = true
	files := readSubnekton(path)
	if len(files) == 0 {
		return nil
	}
	m := core.ReadSeqMap(filepath.Join(r.dir, seqFileName))
	if r.batch != nil {
		m = r.batch.seq // positions this batch issued are not on disk yet
	}
	recs := make([]Record, 0, len(files))
	for _, of := range files {
		rec := Record{ClaimID: of.ClaimID, Envelope: of.Envelope}
		seq, ok := m.Seq[core.EnvelopeKey(of.Envelope)]
		if !ok {
			return ErrNeedsFullOpen // an unnumbered record: only a full Open numbers it as it would
		}
		rec.Seq = seq
		if seq > r.maxSeq {
			r.maxSeq = seq
		}
		recs = append(recs, rec)
	}
	r.dropped += r.settle(recs)
	return nil
}

// loadFor loads what Add needs for env into a write registry: its scope's file.
func (r *Registry) loadFor(env core.Envelope) error {
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return nil // Add reports it
	}
	return r.loadScope(scopeOf(st, claim.ClaimID(payload)))
}

// WriteTo is Write into the store at dir without opening it whole (#248): the cheap path when it can be
// taken, a full Open when it cannot (ErrNeedsFullOpen), with the same result on disk either way.
func WriteTo(dir string, spec claim.Spec, priv ed25519.PrivateKey) (Written, error) {
	r, err := OpenForWrite(dir)
	if err != nil {
		return Written{}, err
	}
	w, err := r.Write(spec, priv)
	if !errors.Is(err, ErrNeedsFullOpen) {
		return w, err
	}
	full, err := Open(dir)
	if err != nil {
		return Written{}, err
	}
	return full.Write(spec, priv)
}

// refuseLegacyLayout looks one level into objects/ (objects/<algo>/<64 hex>.json, the only place the
// 0.2 layout put records) without reading any record.
func refuseLegacyLayout(objectsDir string) error {
	dirs, err := os.ReadDir(objectsDir)
	if err != nil {
		return nil // no objects/ yet: nothing to refuse
	}
	n, first := 0, ""
	for _, d := range dirs {
		if !d.IsDir() || d.Name() == "scope" {
			continue
		}
		files, err := os.ReadDir(filepath.Join(objectsDir, d.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if rel := d.Name() + "/" + f.Name(); legacyLayout.MatchString(rel) {
				if n == 0 {
					first = filepath.Join(objectsDir, d.Name(), f.Name())
				}
				n++
			}
		}
	}
	if n > 0 {
		return legacyLayoutError(objectsDir, n, first)
	}
	return nil
}
