// Package registry is the plankton metadata plane: an append-only log of signed foton
// envelopes, indexed by hash so lineage, discovery, and reuse are O(1) lookups, and
// replicated by set-reconciliation (spec §11, §12). No bytes are stored.
//
// Storage is a content-addressed object store (objects/<algo>/<hash>.json), one file per
// record; indexes are rebuilt on Open; `sync` is "records with seq > cursor". Because each
// object is named by and contains only content-addressed data (no local seq), two registries
// merge conflict-free under git - git itself becomes a federation transport.
package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kton.dev/plankton/core"
)

// ErrNotFoton is returned by Add for a statement that is not a foton. plankton records only
// reproducible results; attestations belong in nekton. Federation Mirror treats this as a
// skip (not an abort), so a foreign/legacy non-foton record cannot wedge a whole sync.
var ErrNotFoton = errors.New("plankton records only fotons; this is an attestation - ingest it with nekton")

// ErrPersist wraps a LOCAL persistence failure (mkdir / marshal / atomic-write) - a TRANSIENT/environmental
// error, as opposed to a record rejected on its merits (bad signature, protocol.ref mismatch, non-canonical
// payload). A federation mirror MUST NOT advance its peer cursor past a record it merely failed to persist
// (that silently, permanently drops a VALID record); it may skip only records that can never become valid.
// See federation.Mirror (round-2 H-e).
var ErrPersist = errors.New("failed to persist record locally")

// Record is one append-only entry: a signed envelope with a local sequence number.
type Record struct {
	Seq      int           `json:"seq"`
	FotonID  string        `json:"fotonId,omitempty"`
	Envelope core.Envelope `json:"envelope"`
}

// Registry indexes an append-log of envelopes rooted at a directory.
type Registry struct {
	dir        string
	objectsDir string
	peersPath  string

	records  []Record        // append order (for sync)
	seen     map[string]bool // recordKey -> present (idempotency)
	keyIdx   map[string]int  // recordKey -> index in records (for twin resolution)
	maxSeq   int
	degraded int // records skipped on load (corrupt or planted-id): a read over this store is INCOMPLETE

	fotonByID map[string]Record // fotonID -> record
	foton     map[string]*core.Foton
	// Verification material (SPEC §8.1), indexed by the subject it is about. Deliberately NOT part
	// of a Record: presence, absence or invalidity must not touch validity or resolvability (§11).
	material map[string][]VerificationMaterial
	byOutput  map[string][]string // output hash -> []fotonID
	byInput   map[string][]string // input hash  -> []fotonID
	byAction  map[string][]string // action key  -> []fotonID
	peers     map[string]int      // peer url -> last remote seq pulled
}

// Open loads (or creates) a registry rooted at dir, replaying its log.
func Open(dir string) (*Registry, error) { return openAt(dir, true) }

// openAt loads a registry. create=false is the READ path (a --source peer): it never MkdirAll's the
// store - a read must not MUTATE the source it reads (and a read-only peer would fail the mkdir with
// "permission denied"). A missing objects dir then simply reads as an empty registry.
func openAt(dir string, create bool) (*Registry, error) {
	r := &Registry{
		dir:        dir,
		objectsDir: filepath.Join(dir, "objects"),
		peersPath:  filepath.Join(dir, "peers.json"),
		seen:      map[string]bool{},
		keyIdx:    map[string]int{},
		fotonByID: map[string]Record{},
		foton:     map[string]*core.Foton{},
		material:  map[string][]VerificationMaterial{},
		byOutput:  map[string][]string{},
		byInput:   map[string][]string{},
		byAction:  map[string][]string{},
		peers:     map[string]int{},
	}
	if create {
		if err := os.MkdirAll(r.objectsDir, 0o755); err != nil {
			return nil, err
		}
	}
	// Replay content-addressed object files in deterministic (sorted) order, so the local
	// sync sequence is stable across clones. One file per record, named by content hash:
	// two registries therefore merge in git conflict-free (disjoint, or byte-identical).
	var paths []string
	if err := filepath.WalkDir(r.objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // no objects dir on a read-only source: an empty registry, not an error
			}
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") && isRecordFile(r.objectsDir, p) {
			paths = append(paths, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var of objectFile
		if err := json.Unmarshal(b, &of); err != nil {
			// A single corrupt/truncated object MUST NOT disable reads over every other (good)
			// record - that would turn one bad byte into a registry-wide DoS. Skip it, name it on
			// stderr, and keep going (the same resilience the viewer already had).
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable record %s: %v\n", p, err)
			r.degraded++
			continue
		}
		r.apply(Record{Seq: r.maxSeq + 1, FotonID: of.FotonID, Envelope: of.Envelope})
	}
	// Verification material is read AFTER the records and never feeds into them: §8.1 requires that
	// its presence, absence or invalidity leave validity and resolvability untouched.
	r.material = readMaterial(r.objectsDir)
	if b, err := os.ReadFile(r.peersPath); err == nil {
		_ = json.Unmarshal(b, &r.peers)
	}
	return r, nil
}

// OpenUnion opens several registries and returns one read-only registry over their UNION, deduped by
// content (a record present in more than one source is applied once, via apply's content key). This is
// pull/union federation: point a reader at N sources and resolve over the union at query time, with no
// copy - the realization of SPEC Clause 11's "union of accessible registries" (and the honest form of
// federation: two strangers meet at a shared hash by both being named as sources, no mirror). The
// union has no backing directory and is read-only.
func OpenUnion(dirs ...string) (*Registry, error) {
	// A named --source that does not exist MUST be an error, not a silently-created empty registry:
	// a closed-world (federated) read that quietly drops an unreachable source asserts coverage it
	// never had - a real join can vanish with no signal. Fail loudly instead (Open would MkdirAll a
	// missing dir and fold in an empty store, counting a phantom source).
	for _, d := range dirs {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("--source %q is not an accessible registry (does the directory exist?)", d)
		}
	}
	if len(dirs) == 1 {
		return openAt(dirs[0], false) // a single --source is a READ; never mkdir the source
	}
	u := &Registry{
		seen:      map[string]bool{},
		keyIdx:    map[string]int{},
		fotonByID: map[string]Record{},
		foton:     map[string]*core.Foton{},
		material:  map[string][]VerificationMaterial{},
		byOutput:  map[string][]string{},
		byInput:   map[string][]string{},
		byAction:  map[string][]string{},
		peers:     map[string]int{},
	}
	for _, d := range dirs {
		r, err := openAt(d, false) // read-only source open: never mutate a peer we only read
		if err != nil {
			return nil, err
		}
		for _, rec := range r.records {
			u.apply(Record{Seq: u.maxSeq + 1, FotonID: rec.FotonID, Envelope: rec.Envelope})
		}
		u.degraded += r.degraded // a skip in ANY source makes the union read incomplete
	}
	return u, nil
}

// Degraded reports how many records were skipped on load (corrupt, or a planted/mismatched id). A
// non-zero count means a read over this registry is INCOMPLETE - a scripted gate should treat it as
// such (see `--strict`), rather than trusting a partial answer.
func (r *Registry) Degraded() int { return r.degraded }

// apply indexes a record already assigned a seq (used during replay).
func (r *Registry) apply(rec Record) {
	// SECURITY: never trust the on-disk fotonId (or the filename) - RE-DERIVE the identity from the
	// envelope. Otherwise a planted file whose stored fotonId equals a target's, but whose envelope is a
	// different (or unsigned) foton, would be indexed under the target's id and silently SHADOW the real
	// record in byOutput/byInput (a `producer` query then answers "(none)"). This is the same check
	// `Add` runs at ingest, just missing on the read path. A foton whose envelope does not hash to its
	// claimed id is skipped and named, reusing the corrupt-record path. (Non-foton records have an empty
	// FotonID and a payload-hash recordKey, which is already self-derived.)
	f, derivedID, perr := parseEnv(rec.Envelope)
	if rec.FotonID != "" {
		if perr != nil || f == nil {
			fmt.Fprintf(os.Stderr, "warning: skipping record claiming id %s: its envelope is not a parseable foton\n", rec.FotonID)
			r.degraded++
			return
		}
		if derivedID != rec.FotonID {
			fmt.Fprintf(os.Stderr, "warning: skipping planted record: claims id %s but its envelope derives %s\n", rec.FotonID, derivedID)
			r.degraded++
			return
		}
		// The rest of what Add enforces, applied HERE too (AUD-09). The read path re-derived the id
		// and stopped, so a record that Add refuses was fully indexed if it arrived by any other
		// route - and both packages document git merge as a supported federation transport, which
		// bypasses Add entirely. Every ingest-gate finding was therefore re-openable through a path
		// the design endorses: a forged protocol.ref made `show` print `command: EVIL` and
		// `records --json` re-serve it to peers.
		//
		// Skipped and counted, not fatal: one planted file must not disable reads over every good
		// record (the corrupt-poisons-read lesson), and `--strict` already refuses to answer over a
		// degraded read for callers who need the loud form.
		if !rec.Envelope.HasSignature() {
			fmt.Fprintf(os.Stderr, "warning: skipping record %s: it carries no signature (SPEC §8; Add refuses these at ingest)\n", rec.FotonID)
			r.degraded++
			return
		}
		if err := f.CheckProtocolRef(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping record %s: %v\n", rec.FotonID, err)
			r.degraded++
			return
		}
	}
	key, _ := recordKey(rec.Envelope, rec.FotonID)
	if i, ok := r.keyIdx[key]; ok {
		// The identity is already present. A same-id TWIN (same covered payload, different signatures - two
		// independent producers, or a corrupt copy planted first) does NOT let first-seen win: UNION the two
		// envelopes' well-formed signatures into one record (red-team round 10, RED-2). The result is
		// order-independent FOR IDENTICAL BYTES - a later mirror of a good source heals a corrupt twin
		// and a second genuine producer's signature is retained, so `producer`/`reproductions` see
		// every signer. `verify` still adjudicates each signature cryptographically.
		//
		// It is NOT order-independent when two records share an id but carry different payloads
		// (different `uri`, say - carried, not covered). unionSignatures refuses those, so which
		// carried variant is stored depends on ingest order. That is a known limitation, stated
		// rather than papered over: the alternative was attaching a signature to bytes its owner
		// never signed, which is what this used to do (#93).
		old := r.records[i].Envelope
		if merged, changed := unionSignatures(old, rec.Envelope); changed {
			r.records[i].Envelope = merged
			if rec.FotonID != "" {
				r.fotonByID[rec.FotonID] = r.records[i]
				if f != nil {
					r.foton[rec.FotonID] = f // same covered id -> inputs/outputs/edges unchanged
				}
			}
		}
		return
	}
	r.keyIdx[key] = len(r.records)
	r.seen[key] = true
	r.records = append(r.records, rec)
	if rec.Seq > r.maxSeq {
		r.maxSeq = rec.Seq
	}
	if rec.FotonID == "" {
		// Not a foton. plankton records only reproducible results; attestations belong in
		// nekton. Older/foreign non-foton records are tolerated on replay but never indexed.
		return
	}
	// f was validated at the top: this record's envelope hashes to rec.FotonID.
	r.fotonByID[rec.FotonID] = rec
	r.foton[rec.FotonID] = f
	for _, o := range f.Outputs {
		r.byOutput[o.Hash] = append(r.byOutput[o.Hash], rec.FotonID)
	}
	for _, in := range f.Inputs {
		r.byInput[in.Hash] = append(r.byInput[in.Hash], rec.FotonID)
	}
	if ak, err := f.ActionKey(); err == nil {
		r.byAction[ak] = append(r.byAction[ak], rec.FotonID)
	}
}

// Add ingests a signed envelope, assigning it a local seq, persisting and indexing it.
// Idempotent: a record already present (by content) returns isNew=false.
func (r *Registry) Add(env core.Envelope) (id string, isNew bool, err error) {
	// Ingest admits only SIGNED records (SPEC §8 / §15): ingest does not VERIFY the signature
	// (that is `plankton verify`), but a record carrying no signature at all is structurally
	// invalid and is rejected - matching nekton, so the shared trust layer behaves the same on
	// both kernels (cold-session finding: plankton used to admit unsigned fotons).
	if !env.HasSignature() {
		return "", false, fmt.Errorf("foton has no signature (SPEC §8: ingest admits only signed records; use `plankton verify` to check authenticity)")
	}
	f, fotonID, err := parseEnv(env)
	if err != nil {
		return "", false, err
	}
	if fotonID == "" {
		return "", false, ErrNotFoton
	}
	// Enforce the §6.2 binding at the trust boundary: a carried descriptor MUST hash to protocol.ref.
	// Without this a forged/stale ref decouples the action key from the real protocol and poisons the
	// reuse cache (cold-session finding).
	if err := f.CheckProtocolRef(); err != nil {
		return "", false, err
	}
	key, err := recordKey(env, fotonID)
	if err != nil {
		return "", false, err
	}
	if r.seen[key] {
		// A record with this identity is already stored. A same-payload / different-signature TWIN is
		// MERGED: persist the UNION of the two envelopes' well-formed signatures on disk (both producers
		// survive, order-independent - red-team round 10, RED-2), then let apply() union it in memory.
		// Subsumes the old heal-a-corrupt-twin case (union keeps only well-formed signatures).
		if i, ok := r.keyIdx[key]; ok {
			merged, err := r.persistRecord(key, fotonID, env)
			if err != nil {
				return "", false, fmt.Errorf("%w: %v", ErrPersist, err)
			}
			r.apply(Record{Seq: r.records[i].Seq, FotonID: fotonID, Envelope: merged})
		}
		return fotonID, false, nil
	}
	merged, err := r.persistRecord(key, fotonID, env)
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrPersist, err)
	}
	rec := Record{Seq: r.maxSeq + 1, FotonID: fotonID, Envelope: merged}
	r.apply(rec)
	return fotonID, true, nil
}

// objectFile is the on-disk form of a record: NO local seq (that is derived on load), so the
// same logical record is byte-identical on every peer - the property that makes a git merge
// of two registries conflict-free.
type objectFile struct {
	FotonID  string        `json:"fotonId,omitempty"`
	Envelope core.Envelope `json:"envelope"`
}

// objectPath maps a record key ("sha256:<hex>") to objects/<algo>/<hex>.json - colon-free
// (Windows-safe) and git-object-like.
func objectPath(objectsDir, recordKey string) string {
	algo, h := "sha256", recordKey
	if i := strings.IndexByte(recordKey, ':'); i >= 0 {
		algo, h = recordKey[:i], recordKey[i+1:]
	}
	return filepath.Join(objectsDir, algo, h+".json")
}

// atomicWrite writes b to path via a temp file + rename, so a concurrent reader (or a crash mid-write)
// never sees a torn/partial object file - rename is atomic on POSIX, and the temp is in the same dir so
// the rename stays on one filesystem. Replaces a bare os.WriteFile, which a second writer could
// interleave into a corrupt file (cold-session concurrency finding).
func atomicWrite(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once renamed
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (r *Registry) writeObject(recordKey string, rec Record) error {
	p := objectPath(r.objectsDir, recordKey)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(objectFile{FotonID: rec.FotonID, Envelope: rec.Envelope}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// Records returns records with seq > since, in append order (the sync feed, spec §12).
func (r *Registry) Records(since int) []Record {
	var out []Record
	for _, rec := range r.records {
		if rec.Seq > since {
			out = append(out, rec)
		}
	}
	return out
}

// MaxSeq is the current local cursor.
func (r *Registry) MaxSeq() int { return r.maxSeq }

// Producer returns foton ids whose output is hash (the lineage join, spec §11).
func (r *Registry) Producer(hash string) []string { return r.byOutput[hash] }

// Uses returns foton ids that consume hash (discovery / alternative scenarios, spec §11).
func (r *Registry) Uses(hash string) []string { return r.byInput[hash] }

// Reuse returns foton ids matching an action key (cache hit, spec §11.3/§11).
func (r *Registry) Reuse(actionKey string) []string { return r.byAction[actionKey] }

// Foton returns the indexed foton for an id.
func (r *Registry) Foton(id string) (*core.Foton, bool) {
	f, ok := r.foton[id]
	return f, ok
}

// Envelope returns the stored envelope for a foton id.
func (r *Registry) Envelope(id string) (core.Envelope, bool) {
	rec, ok := r.fotonByID[id]
	return rec.Envelope, ok
}

// NormalizedOutput returns the output of a foton that consumes `hash` via the normalizer POTENTIAL
// `potential` - i.e. the canonical form THAT normalizer produced from `hash`. Empty if none. The
// potential is identified by its protocol ref (its content-address, the same for every realization
// of one normalizer); for convenience `potential` may also be a normalizer foton id, resolved to its
// ref. This is what makes L1 reproduction-identity a pure graph/hash query: two raw outputs are
// L1-equivalent when the SAME potential normalizes both to a shared hash. Matching the potential
// (not merely the protocol KIND) is required by SPEC §9 - two different normalizers of the same kind
// are different comparisons and must not both satisfy one L1 assertion (cold-session over-claim).
func (r *Registry) NormalizedOutput(hash, potential string) string {
	want := potential
	if f, ok := r.foton[potential]; ok { // a foton id -> resolve to its potential ref
		if ref, err := f.Protocol.EffectiveRef(); err == nil {
			want = ref
		}
	}
	for _, id := range r.byInput[hash] {
		f := r.foton[id]
		if f == nil || len(f.Outputs) == 0 {
			continue
		}
		if ref, err := f.Protocol.EffectiveRef(); err == nil && ref == want {
			return f.Outputs[0].Hash
		}
	}
	return ""
}

// Lineage walks producers of hash backwards, returning visited foton ids (spec §11).
func (r *Registry) Lineage(hash string) []string {
	var order []string
	seen := map[string]bool{}
	var walk func(h string)
	walk = func(h string) {
		for _, id := range r.byOutput[h] {
			if seen[id] {
				continue
			}
			seen[id] = true
			order = append(order, id)
			if f, ok := r.foton[id]; ok {
				for _, in := range f.Inputs {
					walk(in.Hash)
				}
			}
		}
	}
	walk(hash)
	return order
}

// PeerCursor returns the last remote seq pulled from a peer (0 if never).
func (r *Registry) PeerCursor(url string) int { return r.peers[url] }

// SetPeerCursor records the last remote seq pulled from a peer and persists it.
func (r *Registry) SetPeerCursor(url string, seq int) error {
	r.peers[url] = seq
	// peers.json is ONE file every mirror mutates, so two concurrent mirrors would otherwise lose one
	// another's cursor - and a lost cursor is a silently re-fetched or silently skipped range.
	return r.withLock(".peers.lock", func() error {
		on := map[string]int{}
		if b, err := os.ReadFile(r.peersPath); err == nil {
			_ = json.Unmarshal(b, &on)
		}
		for k, v := range r.peers {
			if v > on[k] {
				on[k] = v
			}
		}
		b, err := json.MarshalIndent(on, "", "  ")
		if err != nil {
			return err
		}
		return atomicWrite(r.peersPath, b)
	})
}

// persistRecord is the ONE write path for an object, and the only place a signature union is
// decided. It takes a per-object lock, RE-READS what is on disk, unions against THAT, and writes.
//
// Re-reading under the lock is the whole point. The union used to merge against this process's
// in-memory copy, so two processes co-signing one record each merged their own signature into a
// stale view and the second atomic rename discarded the first's. Atomic rename makes each write
// indivisible; it does nothing for a read-modify-write spanning two of them
// (`concurrency-races`, red-team, VULNERABLE on every run until now).
//
// The lock is per object file, not store-wide: two writers only contend when they touch the same
// record, and a bulk ingest of distinct records has no conflict to serialize.
func (r *Registry) persistRecord(key, fotonID string, env core.Envelope) (core.Envelope, error) {
	merged := env
	err := r.withLock(".obj-"+strings.NewReplacer("/", "_", ":", "_").Replace(key)+".lock", func() error {
		p := objectPath(r.objectsDir, key)
		if b, rerr := os.ReadFile(p); rerr == nil {
			var of objectFile
			if json.Unmarshal(b, &of) == nil && of.Envelope.Payload != "" {
				if m, _ := unionSignatures(of.Envelope, merged); len(m.Signatures) > 0 {
					merged = m
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		b, err := json.MarshalIndent(objectFile{FotonID: fotonID, Envelope: merged}, "", "  ")
		if err != nil {
			return err
		}
		return atomicWrite(p, b)
	})
	return merged, err
}

// Len reports the number of indexed fotons.
func (r *Registry) Len() int { return len(r.foton) }

// FotonIDs returns every indexed foton id, sorted (deterministic output for RDF/JSON export).
func (r *Registry) FotonIDs() []string {
	ids := make([]string, 0, len(r.foton))
	for id := range r.foton {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// --- helpers ---

func parseEnv(env core.Envelope) (*core.Foton, string, error) {
	// CLASS BOUNDARY: the whole payload MUST be valid canonical JSON. FotonID only re-canonicalizes the
	// COVERED projection (inputs/outputs/protocol), so a duplicate key or a >2^53 integer elsewhere in
	// the payload would pass the id check yet mean different things to a first-wins reader. Reject the
	// raw payload here so ingest and read both refuse it (cold-session canonicalization sibling path).
	if pb, err := env.PayloadBytes(); err != nil {
		return nil, "", err
	} else if _, err := core.CanonJSON(pb); err != nil {
		return nil, "", fmt.Errorf("foton payload is not valid canonical JSON: %w", err)
	}
	st, err := env.Statement()
	if err != nil {
		return nil, "", err
	}
	if st.PredicateType != core.PredicateFoton {
		return nil, "", nil
	}
	f, err := st.ToFoton()
	if err != nil {
		return nil, "", err
	}
	id, err := f.FotonID()
	if err != nil {
		return nil, "", err
	}
	return f, id, nil
}

// recordKey is the idempotency key: foton id for fotons, else the payload content hash.
func recordKey(env core.Envelope, fotonID string) (string, error) {
	if fotonID != "" {
		return fotonID, nil
	}
	pb, err := env.PayloadBytes()
	if err != nil {
		return "", err
	}
	return core.HashBytes(pb), nil
}

// envSigOf returns the first signature's bytes (base64) - the field that distinguishes two twins that
// share a payload (hence a recordKey). Empty when unsigned.
func envSigOf(env core.Envelope) string {
	if len(env.Signatures) == 0 {
		return ""
	}
	return env.Signatures[0].Sig
}

// sigWellFormed reports whether the envelope carries a structurally valid Ed25519 signature - a
// non-empty keyid and a signature that base64-decodes to exactly ed25519.SignatureSize bytes. This is
// the only "validity" the kernel can judge WITHOUT the signer's pubkey; it distinguishes a corrupt or
// truncated signature from an intact one, but not an intact-but-wrong one (that needs `verify`).
func sigWellFormed(env core.Envelope) bool {
	if len(env.Signatures) == 0 || env.Signatures[0].KeyID == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	return err == nil && len(sig) == ed25519.SignatureSize
}

// sigEntryWellFormed is the per-signature form of sigWellFormed (a non-empty keyid + a signature that
// base64-decodes to ed25519.SignatureSize bytes), so unionSignatures admits only intact signatures.
func sigEntryWellFormed(keyid, sig string) bool {
	if keyid == "" {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(sig)
	return err == nil && len(b) == ed25519.SignatureSize
}

// unionSignatures merges two twins that share a foton id (a covered-payload hash) but differ in
// signatures into ONE envelope carrying the UNION of their well-formed signatures. A DSSE envelope may
// legitimately hold several signatures over the same PAE (multi-party sign-off, SPEC §8), and the foton
// id covers only the covered projection - so two independent PRODUCERS of an identical computation are
// ONE foton with TWO signatures, not two rival records where ingest/source order decides which signer
// survives (red-team round 10, RED-2). The union is deterministic (dedup by keyid+sig, sorted), hence
// order-independent for identical bytes (SPEC §12 conflict-free union; differing payloads are refused
// above and are order-DEPENDENT in which variant is kept), and it subsumes prefer-valid-twin: only well-formed
// signatures enter the set, so a corrupt twin ingested first is healed by a later good one. Returns the
// merged envelope and whether it differs from `old` (whether a rewrite/reindex is needed).
func unionSignatures(old, incoming core.Envelope) (core.Envelope, bool) {
	// A signature stands over PAE(payloadType, payload). Unioning across DIFFERENT payloads therefore
	// attaches a signature to bytes it never signed - and the identity of a record does not cover
	// everything the payload carries, so two honest producers can collide here: same foton id,
	// different `uri` (carried, not covered, §6.1), different signed bytes.
	//
	// The old code kept the FIRST payload and unioned both signature sets. Demonstrated result: the
	// stored record carried the attacker's locator, the signature list held BOTH keyids, and
	// `plankton verify` with the honest producer's key answered WRONG KEY. The honest producer
	// appeared as an endorser of someone else's payload, and `records --json` republished it.
	//
	// So: never merge across differing bytes. The stored record stays as it is and the caller says
	// so. One of the two carried-field variants wins, which is a real limitation and an honest one -
	// what is NOT acceptable is a keyid attached to bytes its owner did not sign.
	if old.PayloadType != incoming.PayloadType || old.Payload != incoming.Payload {
		return old, false
	}
	type sk struct{ k, s string }
	seen := map[sk]bool{}
	cur := old.Signatures[:0:0]
	add := func(src core.Envelope) {
		for _, s := range src.Signatures {
			if !sigEntryWellFormed(s.KeyID, s.Sig) {
				continue
			}
			key := sk{s.KeyID, s.Sig}
			if seen[key] {
				continue
			}
			seen[key] = true
			cur = append(cur, s)
		}
	}
	add(old)
	add(incoming)
	if len(cur) == 0 {
		return old, false // nothing well-formed to keep; leave the stored record as-is
	}
	sort.Slice(cur, func(i, j int) bool {
		if cur[i].KeyID != cur[j].KeyID {
			return cur[i].KeyID < cur[j].KeyID
		}
		return cur[i].Sig < cur[j].Sig
	})
	changed := len(cur) != len(old.Signatures)
	if !changed {
		for i := range cur {
			if cur[i].KeyID != old.Signatures[i].KeyID || cur[i].Sig != old.Signatures[i].Sig {
				changed = true
				break
			}
		}
	}
	merged := old
	merged.Signatures = cur
	return merged, changed
}

// Unsigned reports how many indexed records lack a well-formed signature. `Add` rejects such records
// at ingest (SPEC §8), but the read path (Open) indexes whatever is on disk without that gate, so a
// record planted directly into objects/ can carry a missing/malformed signature. A --strict caller
// refuses over them. This is a KEYLESS structural check: it catches an absent or corrupt signature,
// NOT an intact-but-wrong one (cryptographic authenticity is `plankton verify` with the signer's key).
func (r *Registry) Unsigned() int {
	n := 0
	for _, rec := range r.records {
		if !sigWellFormed(rec.Envelope) {
			n++
		}
	}
	return n
}

// isRecordFile reports whether p is a canonical object-store record path: objects/<algo>/<hex>.json.
// Only such files are candidate records - a foreign *.json a user dropped under objects/ (a README, a
// config, an export) is NOT a corrupt record and must not count toward the degraded/incomplete tally
// that --strict refuses over (else any stray file false-alarms a strict read).
func isRecordFile(objectsDir, p string) bool {
	rel, err := filepath.Rel(objectsDir, p)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 2 { // must be exactly <algo>/<name>.json
		return false
	}
	name := strings.TrimSuffix(parts[1], ".json")
	if name == "" || name == parts[1] {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false // a record filename is lowercase-hex content hash
		}
	}
	return true
}
