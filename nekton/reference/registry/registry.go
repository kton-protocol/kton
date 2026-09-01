// Package registry is the nekton metadata plane: an append-only log of signed claim
// envelopes, indexed by hash so "what is said about X / by whom / with which predicate /
// about which object" are O(1) lookups (kton SPEC §11–§12). No bytes are stored; records are
// content-addressed by claim id, so two registries merge conflict-free (git as transport).
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
	"time"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

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

// withWriteLock serializes a read-modify-write across INDEPENDENT PROCESSES via an exclusive lock file
// (O_CREATE|O_EXCL, portable - no syscall/build tags), so two processes co-signing the same claim do
// not both read the old envelope and clobber each other (dropping a valid co-signature). A lock left by
// a crashed holder is stolen after a grace period.
func (r *Registry) withWriteLock(fn func() error) error {
	lp := filepath.Join(r.dir, ".objects.lock")
	for attempt := 0; attempt < 2000; attempt++ {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			defer os.Remove(lp)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if fi, e := os.Stat(lp); e == nil && time.Since(fi.ModTime()) > 30*time.Second {
			os.Remove(lp) // steal a stale lock (crashed holder)
			continue
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("could not acquire the object write lock (%s)", lp)
}

// readLegacyObject reads a record an older build left at the flat objects/<algo>/<hash>.json path,
// so a co-signature union and the migrate-on-touch in persistClaim can still find it.
func (r *Registry) readLegacyObject(id string) (core.Envelope, bool) {
	b, err := os.ReadFile(legacyObjectPath(r.objectsDir, id))
	if err != nil {
		return core.Envelope{}, false
	}
	var of objectFile
	if json.Unmarshal(b, &of) != nil {
		return core.Envelope{}, false
	}
	return of.Envelope, true
}

// persistClaim files a claim into its subnekton as a LOCKED on-disk read-modify-write: under the
// write lock it unions the incoming signatures with whatever that subnekton already holds (possibly
// just written by another process), then appends a new record or rewrites the file in place. This
// makes ALL persists of a claim id safe - whether or not this process had yet SEEN the claim - so N
// processes co-signing the same statement concurrently never clobber each other (every co-signature
// survives). Returns the merged envelope actually stored.
func (r *Registry) persistClaim(id, scope string, env core.Envelope) (core.Envelope, error) {
	merged := env
	err := r.withWriteLock(func() error {
		path := subnektonPath(r.objectsDir, scope)
		recs := readSubnekton(path)
		for i, of := range recs {
			if of.ClaimID != id {
				continue
			}
			m, _ := unionSignatures(of.Envelope, env)
			merged, recs[i].Envelope = m, m
			return rewriteSubnekton(path, recs) // an existing entry changed: rewrite the file
		}
		// Not in the subnekton yet. A record an older build left at the flat path is the same claim:
		// union with it and migrate it in, so no co-signature is lost crossing the layouts.
		if disk, ok := r.readLegacyObject(id); ok {
			m, _ := unionSignatures(disk, env)
			merged = m
		}
		if err := appendSubnekton(path, objectFile{ClaimID: id, Envelope: merged}); err != nil {
			return err
		}
		if lp := legacyObjectPath(r.objectsDir, id); lp != "" {
			os.Remove(lp) // no-op unless this was a migration
		}
		return nil
	})
	return merged, err
}

// sigEntryWellFormed reports a structurally intact Ed25519 signature entry (§7.2): a keyid is present
// and the sig base64-decodes to exactly the Ed25519 signature size. This is the only "validity"
// judgeable without the signer's pubkey (a corrupt/truncated sig fails; an intact-but-wrong one needs
// `verify`). A malformed co-signature is dropped from the union rather than poisoning it.
func sigEntryWellFormed(keyid, sig string) bool {
	if keyid == "" {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(sig)
	return err == nil && len(b) == ed25519.SignatureSize
}

// unionSignatures merges two twins that share a claim id (a payload hash) but differ in signatures
// into ONE DSSE envelope carrying the UNION of their well-formed signatures. A DSSE envelope may
// legitimately hold several signatures over the same PAE (multi-party sign-off, SPEC §8), and the
// claim id covers only the payload - so two independent co-signers of an identical statement are ONE
// claim with TWO signatures, not two rival records where ingest order decides which signature
// survives. The union is deterministic (dedup by keyid+sig, sorted), so it is order-independent: any
// merge order of the same sources yields byte-identical signatures (SPEC §12 conflict-free union).
// This also subsumes prefer-valid-twin: only well-formed signatures enter the set, so a corrupt twin
// ingested first is healed by a later mirror of the good one (its malformed sig is simply excluded).
// Returns the merged envelope and whether it differs from old (whether a rewrite/reindex is needed).
func unionSignatures(old, incoming core.Envelope) (core.Envelope, bool) {
	type sk struct{ k, s string }
	seen := map[sk]bool{}
	cur := old.Signatures[:0:0] // empty slice of the same (anonymous) element type
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

// Record is one append-only entry: a signed claim envelope with a local sequence number.
type Record struct {
	Seq      int           `json:"seq"`
	ClaimID  string        `json:"claimId"`
	Envelope core.Envelope `json:"envelope"`
}

// Registry indexes an append-log of claim envelopes rooted at a directory (SPEC §11).
type Registry struct {
	dir        string
	objectsDir string
	peersPath  string

	records []Record
	seen    map[string]bool // claim id -> present (idempotency)
	maxSeq  int
	dropped int // on-disk records dropped as orphans / chain-invalid on load (§7.4)

	claimByID   map[string]Record
	bySubject   map[string][]int // subject key (hash/uri) -> record indices
	byPredicate map[string][]int // predicate term key      -> record indices
	bySigner    map[string][]int // keyid                   -> record indices
	byObject    map[string][]int // object key (hash/uri)   -> record indices

	// Scope/seed/chain bookkeeping (SPEC §7.4).
	seeds   map[string]bool            // scope_id -> seed present
	inScope map[string]map[string]bool // scope_id -> set of in-scope claim ids

	// unresolved: scope_id -> count of PERSISTED claims that name this scope but do not resolve (their
	// prev/seed is missing). A non-zero count means the scope may be TRUNCATED - a withheld middle claim
	// leaves later claims (possibly the sealed head) unreachable, so the resolved tip is NOT necessarily
	// the real head. Surfaced by `head` so a truncation is never silent.
	unresolved map[string]int

	peers map[string]int
}

// Open loads (or creates) a registry rooted at dir, replaying its append log.
func Open(dir string) (*Registry, error) { return openAt(dir, true) }

// OpenUnion opens one or more registries READ-ONLY and returns a registry over their union, deduped by
// claim id and chain-settled. A single source is simply read (never mkdir'd, so a read-only peer or
// --source cannot fail the open or be mutated); multiple sources realize SPEC Clause 11's "union of
// accessible registries" for a reader, with no copy. The result is read-only (no records are persisted).
func OpenUnion(dirs ...string) (*Registry, error) {
	if len(dirs) == 0 {
		return nil, fmt.Errorf("OpenUnion: no sources given")
	}
	for _, d := range dirs {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("source %q is not an accessible registry (does the directory exist?)", d)
		}
	}
	u, err := openAt(dirs[0], false)
	if err != nil {
		return nil, err
	}
	if len(dirs) == 1 {
		return u, nil
	}
	var pending []Record
	for _, d := range dirs[1:] {
		src, err := openAt(d, false)
		if err != nil {
			return nil, err
		}
		pending = append(pending, src.RawRecords()...)
	}
	u.dropped += u.settle(pending)
	return u, nil
}

// openAt loads a registry. create=false is the READ path (a peer being mirrored, or a --source): it
// never MkdirAll's the store - a read must not MUTATE the source it reads, and a read-only peer would
// otherwise fail the mkdir with "permission denied". A missing objects dir then reads as an empty
// registry.
func openAt(dir string, create bool) (*Registry, error) {
	r := &Registry{
		dir:         dir,
		objectsDir:  filepath.Join(dir, "objects"),
		peersPath:   filepath.Join(dir, "peers.json"),
		seen:        map[string]bool{},
		claimByID:   map[string]Record{},
		bySubject:   map[string][]int{},
		byPredicate: map[string][]int{},
		bySigner:    map[string][]int{},
		byObject:    map[string][]int{},
		seeds:       map[string]bool{},
		inScope:     map[string]map[string]bool{},
		unresolved:  map[string]int{},
		peers:       map[string]int{},
	}
	if create {
		if err := os.MkdirAll(r.objectsDir, 0o755); err != nil {
			return nil, err
		}
	}
	format, err := readStoreFormat(r.objectsDir)
	if err != nil {
		return nil, err
	}
	if format > StoreFormat {
		return nil, fmt.Errorf("nekton store at %s is layout format %d, this build reads format %d.\n"+
			"Upgrade nekton instead of reading it with this build: an unreadable store must not be\n"+
			"mistaken for an empty one.", dir, format, StoreFormat)
	}
	if create {
		if err := writeStoreFormat(r.objectsDir); err != nil {
			return nil, err
		}
	}
	pending, err := readStore(r.objectsDir)
	if err != nil {
		return nil, err
	}
	// Objects on disk are sorted by content hash, NOT chain order, and a git-merged/planted object
	// could be an orphan. So replay is chain-VALIDATING: index records whose §7.4 chain resolves
	// against the state so far, settling repeatedly (a child waits for its seed/prev), then DROP
	// whatever never resolves - a tampered or reordered object cannot be silently trusted on load.
	r.dropped = r.settle(pending)
	if b, err := os.ReadFile(r.peersPath); err == nil {
		_ = json.Unmarshal(b, &r.peers)
	}
	return r, nil
}

// settle indexes records whose §7.4 chain resolves against the current state, repeating until a
// full pass adds nothing (a scoped child settles once its seed + prev are indexed), then drops
// the remainder as orphans / structurally-invalid. Used on replay so a planted or reordered
// on-disk object is not trusted, and reusable for out-of-order federation batches.
func (r *Registry) settle(pending []Record) (dropped int) {
	for {
		progress := false
		var next []Record
		for _, rec := range pending {
			if r.seen[rec.ClaimID] {
				continue
			}
			st, _, err := claim.ParseEnvelope(rec.Envelope)
			if err != nil {
				continue // unparseable → drop
			}
			p, _ := st.ParsePredicate()
			if err := r.checkChain(rec.ClaimID, st, p); err != nil {
				next = append(next, rec) // not (yet) valid - defer to a later pass
				continue
			}
			rec.Seq = r.maxSeq + 1
			r.index(rec)
			progress = true
		}
		pending = next
		if !progress {
			// Whatever never resolved is a persisted-but-unreachable successor. Record the scope it names
			// so `head` can flag a possible TRUNCATION (a withheld middle claim), rather than silently
			// presenting the shortened chain's tip as the sealed head.
			for _, rec := range pending {
				if st, _, err := claim.ParseEnvelope(rec.Envelope); err == nil {
					if p, e := st.ParsePredicate(); e == nil && p.Scope != "" {
						if r.unresolved == nil {
							r.unresolved = map[string]int{}
						}
						r.unresolved[p.Scope]++
					}
				}
			}
			return len(pending)
		}
	}
}

// Unresolved reports how many persisted claims name this scope but do not resolve (a missing prev/seed)
// - a non-zero count means the scope may be TRUNCATED and its reported head is only provisional.
func (r *Registry) Unresolved(scope string) int { return r.unresolved[scope] }

// index records + indexes a claim already assigned a seq (used during replay and after Add).
func (r *Registry) index(rec Record) {
	// SECURITY: RE-DERIVE the claim id from the envelope; never trust the on-disk claimId (or filename).
	// A planted file whose stored claimId equals a target's, but whose envelope is a different claim,
	// would otherwise SHADOW the real claim in bySubject/bySigner/byPredicate - so `nekton about`/`by`
	// answer "(none)" for a suppressed fail review. This is the check `Add` runs at ingest, missing on
	// the read path.
	st, payload, err := claim.ParseEnvelope(rec.Envelope)
	if err == nil && rec.ClaimID != "" {
		if derived := claim.ClaimID(payload); derived != rec.ClaimID {
			fmt.Fprintf(os.Stderr, "warning: skipping planted claim: stored id %s but its envelope derives %s\n", rec.ClaimID, derived)
			return
		}
	}
	if r.seen[rec.ClaimID] {
		return
	}
	r.seen[rec.ClaimID] = true
	r.records = append(r.records, rec)
	if rec.Seq > r.maxSeq {
		r.maxSeq = rec.Seq
	}
	idx := len(r.records) - 1
	r.claimByID[rec.ClaimID] = rec
	if err != nil {
		return
	}
	p, _ := st.ParsePredicate()
	for _, s := range st.Subject {
		if k := s.Key(); k != "" {
			r.bySubject[k] = append(r.bySubject[k], idx)
		}
	}
	// Index under EVERY signer keyid (an envelope may carry several co-signatures over one payload), so
	// `by signer` finds a co-signed claim under each of its signers, not just the first.
	seenKey := map[string]bool{}
	for _, s := range rec.Envelope.Signatures {
		if s.KeyID == "" || seenKey[s.KeyID] {
			continue
		}
		seenKey[s.KeyID] = true
		r.bySigner[s.KeyID] = append(r.bySigner[s.KeyID], idx)
	}
	if p != nil {
		if k := p.Predicate.Key(); k != "" {
			r.byPredicate[k] = append(r.byPredicate[k], idx)
		}
		if k := p.Object.Key(); k != "" {
			r.byObject[k] = append(r.byObject[k], idx)
		}
		// scope/seed bookkeeping
		if st.IsSeed() {
			r.seeds[rec.ClaimID] = true
			if r.inScope[rec.ClaimID] == nil {
				r.inScope[rec.ClaimID] = map[string]bool{}
			}
		} else if p.Scope != "" {
			if r.inScope[p.Scope] == nil {
				r.inScope[p.Scope] = map[string]bool{}
			}
			r.inScope[p.Scope][rec.ClaimID] = true
		}
	}
}

// reindexSigners adds record idx to bySigner for any signer keyid present in `after` but not in
// `before` - used when a twin merge grows an already-indexed record's signature set with a new
// co-signer, so `by signer` immediately finds the claim under the added key without a full replay.
func (r *Registry) reindexSigners(idx int, before, after core.Envelope) {
	had := map[string]bool{}
	for _, s := range before.Signatures {
		had[s.KeyID] = true
	}
	for _, s := range after.Signatures {
		if s.KeyID == "" || had[s.KeyID] {
			continue
		}
		had[s.KeyID] = true
		r.bySigner[s.KeyID] = append(r.bySigner[s.KeyID], idx)
	}
}

// Add ingests a signed claim envelope: verifies structural validity + the scope chain (SPEC
// §7.4), persists it, and indexes it. Idempotent by claim id. Signature verification against a
// trusted key is a `verify`/trust-policy concern (out of the kernel, SPEC §8); Add requires only
// that a signature is present.
func (r *Registry) Add(env core.Envelope) (id string, isNew bool, err error) {
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return "", false, err
	}
	if !env.HasSignature() {
		return "", false, fmt.Errorf("claim has no signature (SPEC §7.2: a claim is constituted by its signature)")
	}
	id = claim.ClaimID(payload)
	if r.seen[id] {
		// A same-payload / different-signature TWIN of an already-stored claim: UNION the two envelopes'
		// signatures (a claim id covers only the payload, so two independent co-signers of an identical
		// statement are ONE claim with TWO signatures). The merge is deterministic, so any ingest/mirror
		// order of the same sources converges to byte-identical signatures - no valid co-signature is
		// dropped, and a corrupt twin is healed by a later good one. The claim's content (subject/
		// predicate/object, chain position) is unchanged; only the stored envelope's signature set grows,
		// so we rewrite it and index the record under any newly-added signer keyid.
		if old, ok := r.claimByID[id]; ok {
			// A same-payload TWIN: persist the co-signature union under the lock (re-reading the current
			// on-disk envelope), then refresh this process's in-memory view + signer index.
			merged, err := r.persistClaim(id, scopeOf(st, id), env)
			if err != nil {
				return "", false, err
			}
			rec := Record{Seq: old.Seq, ClaimID: id, Envelope: merged}
			r.claimByID[id] = rec
			for i := range r.records {
				if r.records[i].ClaimID == id {
					r.records[i] = rec
					r.reindexSigners(i, old.Envelope, merged)
					break
				}
			}
		}
		return id, false, nil
	}
	p, perr := st.ParsePredicate()
	if perr != nil {
		return "", false, perr
	}
	if err := st.Validate(p); err != nil {
		return "", false, err // structurally invalid: reject
	}
	// Classify the chain check. A STRUCTURAL violation (a malformed seed/genesis, a scoped claim with no
	// prev) is permanently invalid and is rejected BEFORE persisting. An UNRESOLVED reference (the
	// scope's seed or the prev is simply not present yet - common in a federated store) is INCOMPLETE,
	// not invalid (SPEC §11): PERSIST it and DEFER indexing, so a later mirror of the missing dependency
	// settles it. It never joins a resolved head or an in-scope set until it resolves, so sealed-scope
	// tamper-evidence is unaffected - a dropped link leaves its successors unresolved and the published
	// head no longer reproduces.
	chainErr := r.checkChain(id, st, p)
	if chainErr != nil && !errors.Is(chainErr, errUnresolved) {
		return "", false, chainErr
	}
	// Persist through the locked union-write too: a DIFFERENT process may already have created this
	// object (this process just had not SEEN it), so a plain clobber here would drop its co-signature.
	merged, err := r.persistClaim(id, scopeOf(st, id), env)
	if err != nil {
		return "", false, err
	}
	rec := Record{Seq: r.maxSeq + 1, ClaimID: id, Envelope: merged}
	if chainErr != nil { // errUnresolved: persisted, awaiting its dependency
		if p != nil && p.Scope != "" {
			r.unresolved[p.Scope]++ // may be a withheld-middle successor -> `head` flags a truncation
		}
		return id, true, nil
	}
	r.index(rec)
	return id, true, nil
}

// scopeOf reports which subnekton a claim belongs to: a seed opens - and belongs to - its own scope
// (scope_id = its claim id, §7.4), a scoped claim names one, an unscoped claim belongs to the
// unscoped nekton. This is read from the SIGNED payload, so it is available even when the claim
// cannot yet be indexed: a claim whose seed or prev has not arrived is still filed in the right
// nekton while it waits (SPEC §11: incomplete, not invalid). A malformed predicate files as
// unscoped; Add rejects it a moment later on its own merits.
func scopeOf(st *claim.Statement, id string) string {
	if st == nil {
		return ""
	}
	if st.IsSeed() {
		return id
	}
	p, err := st.ParsePredicate()
	if err != nil || p == nil {
		return ""
	}
	return p.Scope
}

// checkChain enforces the §7.4 structural grammar on ingest: a seed opens a scope; a scoped
// non-genesis claim MUST name an existing scope and a `prev` that resolves in-scope (or the
// seed itself as the first link). Removal/reorder leaves a dangling `prev` and is rejected -
// the tamper-evidence guarantee. Meaning of `responsible`/registration/sealing stays a
// consumer concern, not enforced here.
func (r *Registry) checkChain(id string, st *claim.Statement, p *claim.Predicate) error {
	if p == nil {
		return nil
	}
	// A top-level `genesis` field is never valid (genesis lives inside a scope/v0 predicate, §7.4);
	// reject it so it cannot slip past the predicate.genesis guard below (cold-session finding).
	if st.Genesis {
		return fmt.Errorf("genesis must live inside a scope/v0 predicate, not at the statement top level (SPEC §7.4)")
	}
	if st.IsSeed() {
		// A seed opens its own scope (scope_id = this claim id). SPEC §7.4: it MUST set genesis
		// and MUST NOT carry prev.
		if p.Prev != "" {
			return fmt.Errorf("a seed MUST NOT carry prev (SPEC §7.4)")
		}
		if !p.Genesis {
			return fmt.Errorf("a scope seed MUST set genesis:true (SPEC §7.4)")
		}
		return nil
	}
	// genesis:true is a seed-only structural flag; on a non-seed it is an attempt to mint a
	// scope without a scope/v0 statement - reject it (defense for the §7.4 identity guarantee).
	if p.Genesis {
		return fmt.Errorf("genesis:true is only valid on a scope/v0 seed (SPEC §7.4)")
	}
	if p.Scope == "" {
		return nil // unscoped claim - allowed (SPEC §7.4 governs only scoped statements)
	}
	if !r.seeds[p.Scope] {
		// UNRESOLVED (not malformed): the scope's seed may simply not be mirrored yet. Defer.
		return fmt.Errorf("scoped claim names scope %s whose seed is not present yet: %w", p.Scope, errUnresolved)
	}
	if p.Prev == "" {
		return fmt.Errorf("scoped claim %s must carry prev", id) // structural: reject
	}
	if p.Prev != p.Scope && !r.inScope[p.Scope][p.Prev] {
		// UNRESOLVED: the prev may arrive from another peer; a genuine drop/reorder never resolves and
		// stays a deferred orphan (never in the head), which is what preserves tamper-evidence.
		return fmt.Errorf("prev %s does not resolve in scope %s yet: %w", p.Prev, p.Scope, errUnresolved)
	}
	return nil
}

// errUnresolved marks a chain check that FAILED only because a referenced seed/prev is not present yet
// (as opposed to a structurally-invalid claim). Such a claim is persisted and deferred, not rejected.
var errUnresolved = errors.New("unresolved chain reference")

// objectFile is the on-disk record form: no local seq (derived on load), so the same logical
// claim is byte-identical on every peer - making a git merge of two registries conflict-free.
type objectFile struct {
	ClaimID  string        `json:"claimId"`
	Envelope core.Envelope `json:"envelope"`
}

// splitID separates "sha256:<hex>" into its algorithm and bare hex, defaulting to sha256.
func splitID(id string) (algo, hex string) {
	algo, hex = "sha256", id
	if i := strings.IndexByte(id, ':'); i >= 0 {
		algo, hex = id[:i], id[i+1:]
	}
	return algo, hex
}

// StoreFormat is the on-disk layout revision of a nekton store, recorded in objects/.format.
//
//	1  one JSON file per claim (objects/<algo>/<hex>.json)
//	2  one JSONL file per subnekton (#41), plus the format marker
//
// The marker exists so that a store written by a NEWER build fails loudly on an older one instead
// of reading as empty. It cannot rescue the 1 -> 2 step itself: a 0.1 binary looks for
// objects/**/*.json, finds none, and reports an empty registry with exit 0 - a verification tool
// answering "nothing recorded" where the truthful answer is "I cannot read this store". That is
// unfixable in retrospect, and is the reason the subnekton layout ships as 0.2 rather than a patch.
// From format 2 on, a store says what it is.
const StoreFormat = 2

const formatMarker = ".format"

// readStoreFormat returns the recorded format, or 0 when the store carries no marker (a format-1
// store, an empty directory, or one written by a 0.2 build from before the marker existed).
func readStoreFormat(objectsDir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(objectsDir, formatMarker))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var name string
	var v int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%s %d", &name, &v); err != nil || name != "nekton-store" || v < 1 {
		return 0, fmt.Errorf("nekton store marker %s is not readable (%q); refusing to guess the layout",
			filepath.Join(objectsDir, formatMarker), strings.TrimSpace(string(b)))
	}
	return v, nil
}

// writeStoreFormat records the marker. Write path only - a read must never mutate its source.
func writeStoreFormat(objectsDir string) error {
	have, err := readStoreFormat(objectsDir)
	if err != nil || have == StoreFormat {
		return err
	}
	return os.WriteFile(filepath.Join(objectsDir, formatMarker),
		[]byte(fmt.Sprintf("nekton-store %d\n", StoreFormat)), 0o644)
}

// subnektonPath is where a claim lives: ONE FILE PER SUBNEKTON, named by the scope id (the seed's
// own hash, SPEC §7.4), plus one file for the unscoped nekton.
//
//	objects/scope/<scope_id>.nekton.jsonl    a subnekton - its seed and every claim chained under it
//	objects/unscoped.nekton.jsonl            the unscoped nekton
//
// A scope is a bounded, federatable sub-registry (seed.go), and this gives it one artifact: a thing
// that can be chmod'd, sparse-checked-out, copied, or handed over whole - none of which a flat pile
// of per-claim hashes can be. The file is a BAG, not a sequence: order stays the chain's alone
// (`prev`), so the file never becomes a second, unsigned representation of order that could drift
// from the signed one. JSONL so a new claim is an append, not a rewrite of the subnekton.
func subnektonPath(objectsDir, scope string) string {
	if scope == "" {
		return filepath.Join(objectsDir, "unscoped.nekton.jsonl")
	}
	_, s := splitID(scope)
	return filepath.Join(objectsDir, "scope", s+".nekton.jsonl")
}

// legacyObjectPath is the per-claim path every record had before the store gained subnekton files.
// Reads still resolve it (openAt walks both forms), and persistClaim migrates a record in the first
// time a write touches it.
func legacyObjectPath(objectsDir, claimID string) string {
	algo, h := splitID(claimID)
	return filepath.Join(objectsDir, algo, h+".json")
}

// readSubnekton parses a subnekton file into its records. It is deliberately TOLERANT: one corrupt
// or half-written line must not disable reads over every other record in the scope, so a bad line is
// named on stderr and skipped. A missing file is an empty subnekton, not an error.
func readSubnekton(path string) []objectFile {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []objectFile
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var of objectFile
		if err := json.Unmarshal([]byte(line), &of); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable record in %s: %v\n", path, err)
			continue
		}
		out = append(out, of)
	}
	return out
}

// marshalRecord renders one record as a single JSONL line.
func marshalRecord(of objectFile) ([]byte, error) {
	b, err := json.Marshal(of)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// appendSubnekton adds a record to its subnekton. An append (not a rewrite) so filing the Nth claim
// costs one line, never N. A crash mid-append leaves a torn final line, which readSubnekton skips -
// the record is then simply absent, exactly as if it had never been filed.
func appendSubnekton(path string, of objectFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	line, err := marshalRecord(of)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rewriteSubnekton replaces a subnekton file atomically - the path taken when an EXISTING entry
// changes (a co-signature union), which an append cannot express.
func rewriteSubnekton(path string, recs []objectFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var buf []byte
	for _, of := range recs {
		line, err := marshalRecord(of)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
	}
	return atomicWrite(path, buf)
}

// normKey canonicalizes a hash lookup argument to lowercase (SPEC §5.1) so a query resolves under
// the same key the index was built with (Subject.Key normalizes too); a URI passes through.
func normKey(key string) string {
	if norm, ok := core.NormalizeContentHash(key); ok {
		return norm
	}
	return key
}

// About returns the claims whose subject == key (a "sha256:..." hash or a URI), over this
// registry (SPEC §11 subject resolution; union-of-registries is a federation concern).
func (r *Registry) About(key string) []Record { return r.at(r.bySubject[normKey(key)]) }

// BySigner returns claims signed by keyid.
func (r *Registry) BySigner(keyid string) []Record { return r.at(r.bySigner[keyid]) }

// ByPredicate returns claims whose relation term == key.
func (r *Registry) ByPredicate(key string) []Record { return r.at(r.byPredicate[key]) }

// ByObject returns claims whose object == key.
func (r *Registry) ByObject(key string) []Record { return r.at(r.byObject[normKey(key)]) }

// Claim returns the record for a claim id.
func (r *Registry) Claim(id string) (Record, bool) { rec, ok := r.claimByID[id]; return rec, ok }

// IsSeed reports whether id is a scope seed present in this registry.
func (r *Registry) IsSeed(id string) bool { return r.seeds[id] }

// Heads returns the tip(s) of a scope's hash chain: the in-scope claim(s) that no other in-scope
// claim names as prev (SPEC §7.4). Because each claim id covers its prev (claim.ClaimID), a head
// transitively commits to the whole chain behind it - publishing (or `kton anchor`-ing) the head
// makes every prior edit in the scope tamper-evident. A linear chain has exactly one head; a
// branched scope has several. A scope with no chained claims yet has the seed itself as its head.
// chainLen counts the in-scope claims (excluding the seed). ok is false if scope is not a known seed.
func (r *Registry) Heads(scope string) (heads []string, chainLen int, ok bool) {
	if !r.seeds[scope] {
		return nil, 0, false
	}
	members := r.inScope[scope] // set of in-scope claim ids (the seed itself is not a member)
	chainLen = len(members)
	if chainLen == 0 {
		return []string{scope}, 0, true // empty scope: the seed is the tip
	}
	referenced := map[string]bool{} // every prev pointed at from within the scope
	for id := range members {
		rec, present := r.claimByID[id]
		if !present {
			continue
		}
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		p, err := st.ParsePredicate()
		if err != nil {
			continue
		}
		if p.Prev != "" {
			referenced[p.Prev] = true
		}
	}
	for id := range members {
		if !referenced[id] { // nothing chains onward from id -> it is a leaf
			heads = append(heads, id)
		}
	}
	sort.Strings(heads)
	return heads, chainLen, true
}

func (r *Registry) at(idxs []int) []Record {
	out := make([]Record, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, r.records[i])
	}
	return out
}

// Records returns records with seq > since, in append order (the sync feed, SPEC §12).
// Dropped reports how many on-disk records were dropped as orphans / chain-invalid on load (§7.4).
func (r *Registry) Dropped() int { return r.dropped }

// RawRecords returns every record on disk (pre-settle), including orphans Open would drop. Used by
// federation: the RECEIVER decides validity against its OWN union (like Add), not the sender's, so a
// peer's orphan whose parent the receiver already holds still transfers.
func (r *Registry) RawRecords() []Record {
	out, _ := readStore(r.objectsDir)
	return out
}

// readStore reads EVERY record a store holds, in both forms: the nekton files
// (objects/**/*.nekton.jsonl, one record per line) and the legacy per-claim objects
// (objects/<algo>/<hash>.json) an older build wrote. It is the ONE place that knows the on-disk
// form - openAt and RawRecords both go through it, so a caller can never drift from the layout and
// silently read half a store. Order is stable (sorted paths, then file order); it carries no
// meaning, since a scope's order is its `prev` chain.
func readStore(objectsDir string) (recs []Record, hardErr error) {
	var nektons, legacy []string
	if err := filepath.WalkDir(objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // no objects dir on a read-only source: an empty store, not an error
			}
			return err
		}
		switch {
		case d.IsDir():
		case strings.HasSuffix(p, ".nekton.jsonl"):
			nektons = append(nektons, p)
		case strings.HasSuffix(p, ".json"):
			legacy = append(legacy, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(nektons)
	sort.Strings(legacy)
	for _, p := range nektons {
		for _, of := range readSubnekton(p) {
			recs = append(recs, Record{ClaimID: of.ClaimID, Envelope: of.Envelope})
		}
	}
	for _, p := range legacy {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var of objectFile
		if err := json.Unmarshal(b, &of); err != nil {
			// A single corrupt object MUST NOT disable reads over every other (good) record - one
			// bad byte would otherwise be a store-wide DoS. Skip it, name it on stderr, keep going.
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable record %s: %v\n", p, err)
			continue
		}
		recs = append(recs, Record{ClaimID: of.ClaimID, Envelope: of.Envelope})
	}
	return recs, nil
}

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

// Len reports the number of indexed claims.
func (r *Registry) Len() int { return len(r.claimByID) }

// PeerCursor / SetPeerCursor track replication progress against a peer.
func (r *Registry) PeerCursor(url string) int { return r.peers[url] }

// SetPeerCursor records and persists the last remote seq pulled from a peer.
func (r *Registry) SetPeerCursor(url string, seq int) error {
	r.peers[url] = seq
	b, err := json.MarshalIndent(r.peers, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.peersPath, b, 0o644)
}
