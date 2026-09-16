// Package registry is the nekton metadata plane: an append-only log of signed claim
// envelopes, indexed by hash so "what is said about X / by whom / with which predicate /
// about which object" are O(1) lookups (kton SPEC §11–§12). No bytes are stored; records are
// content-addressed by claim id, so two registries merge conflict-free (git as transport).
package registry

import (
	"bufio"
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
// resolveSeqs returns the durable federation position of every id, issuing one to any id that does
// not have one yet (SPEC §12; see core.SeqMap for why the numbering lives beside the records).
// persist=false is the read-only source path: it numbers in memory and writes nothing, because a
// read MUST NOT mutate the store it reads.
//
// It must NOT be called with the object write lock already held - it takes that lock itself.
func (r *Registry) resolveSeqs(ids []string, persist bool) (map[string]int, error) {
	p := filepath.Join(r.dir, seqFileName)
	m := core.ReadSeqMap(p)
	r.epoch = m.Epoch
	need := false
	for _, id := range ids {
		if _, ok := m.Seq[id]; !ok && id != "" {
			need = true
			break
		}
	}
	if !need || !persist {
		m.Assign(ids) // in-memory only: nothing new to record, or a read-only source
		return m.Seq, nil
	}
	var out map[string]int
	err := r.withWriteLock(func() error {
		m := core.ReadSeqMap(p) // re-read under the lock: another process may have issued positions
		r.epoch = m.Epoch
		if m.Assign(ids) {
			if err := core.WriteSeqMap(p, m); err != nil {
				return err
			}
		}
		out = m.Seq
		return nil
	})
	return out, err
}

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
	path, perr := subnektonPath(r.objectsDir, scope)
	if perr != nil {
		return env, perr
	}
	err := r.withWriteLock(func() error {
		// Union across EVERY line that carries this claim id - after this change there can be more
		// than one, each recording a signature set as it arrived.
		recs := readSubnekton(path)
		held, found := core.Envelope{}, false
		for _, of := range recs {
			if of.ClaimID != id {
				continue
			}
			// The `claimId` FIELD is not evidence that the line is this claim. A planted line - the
			// target's id, a different claim's envelope - used to be taken as a prior record of the
			// target: unionSignatures keeps the first when the payloads differ, so `merged` became
			// the planted envelope, `Add` returned it as the stored record, and the result was
			//
			//     isNew=true  err=<nil>   Len()=0   Claim(target) held=false
			//
			// a successful ingest of a claim the registry does not hold and cannot return. Because
			// the planted line wins every time, re-ingesting the authentic claim could never repair
			// the store. The record built from it then reached the sync feed as well.
			//
			// A claim id IS sha256(canon(Statement)), so the line either derives its own id or it is
			// not this claim. Identity, not the field - the same rule persistRecord learned on the
			// plankton side, where it also preserves the legitimate case: a co-signed twin carries
			// the same payload and therefore the same id, and still merges.
			if !derivesClaimID(of.Envelope, id) {
				continue
			}
			if !found {
				held, found = of.Envelope, true
				continue
			}
			held, _ = unionSignatures(held, of.Envelope)
		}
		if found {
			m, changed := unionSignatures(held, env)
			merged = m
			if !changed {
				return nil // already have every signature: writing a line would only grow the file
			}
			// APPEND, do not rewrite. The subnekton is append-only because in nekton the order
			// carries meaning (prev, head, seal); rewriting an entry in place erased the record that
			// anything had changed, and with it the only thing a cursor could have noticed.
			// The line holds the envelope AS IT ARRIVED - the reader unions, which is what settle and
			// Add already do for a twin.
			return appendSubnekton(path, objectFile{ClaimID: id, Envelope: env})
		}
		// Not in the subnekton yet. A record an older build left at the flat path is the same claim:
		// union with it and migrate it in, so no co-signature is lost crossing the layouts.
		// Same rule for a record an older build left at the flat path: migrate it only if it IS this
		// claim. A file named by the target that holds something else is not a co-signature to
		// preserve, and carrying it across the layouts would plant it in the new one.
		if disk, ok := r.readLegacyObject(id); ok && derivesClaimID(disk, id) {
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

// VerificationMaterial is external evidence ABOUT a record - who signed it, or that it existed by a
// given time - bound to the record by its content address (SPEC §8.1).
//
// The kernel NEVER interprets Material. It is opaque bytes produced by some other scheme (a Sigstore
// bundle, a Rekor entry, an RFC 3161 token, an X.509 detached signature, a qualified eIDAS
// signature), and deciding which issuers count is a consumer concern - the same split as trust
// policy, for the same reason: whose word counts is not a property of the record.
type VerificationMaterial struct {
	Subject   string `json:"subject"`   // the record's content address - claim id or foton id
	Scheme    string `json:"scheme"`    // what produced Material; an UNKNOWN scheme is carried, never rejected
	MediaType string `json:"mediaType"` // how to read Material
	Material  string `json:"material"`  // base64 of the scheme's own artifact
}

// Registry indexes an append-log of claim envelopes rooted at a directory (SPEC §11).
type Registry struct {
	dir        string
	objectsDir string
	peersPath  string

	records []Record
	// feed is what §12's sync(since) answers from: every LINE the store holds that passed the
	// structural gate, each with its own position, in the order they were written. It is
	// deliberately NOT the index.
	//
	// Two things follow, and both were bugs before. A claim whose seed or prev is not held
	// is persisted and structurally valid - incomplete is not invalid (§11) - so it is in the feed
	// even though it answers no query; it used to be in neither, so a peer never received it at all,
	// and when it later resolved locally it entered the index at its original position, below every
	// cursor already issued. And a co-signature is its OWN line, so it has its own position and is
	// delivered like anything else; the reader unions lines that share a claim id, exactly as `Add`
	// unions a twin at ingest.
	feed          []Record
	deferredCount int
	seen          map[string]bool // claim id -> present (idempotency)
	maxSeq        int
	epoch         string // the numbering this store's cursors belong to (core.SeqMap.Epoch)
	dropped       int    // on-disk records dropped as orphans / chain-invalid on load (§7.4)

	claimByID   map[string]Record
	bySubject   map[string][]int // subject key (hash/uri) -> record indices
	byPredicate map[string][]int // predicate term key      -> record indices
	bySigner    map[string][]int // keyid                   -> record indices
	byObject    map[string][]int // object key (hash/uri)   -> record indices

	// Scope/seed/chain bookkeeping (SPEC §7.4).
	seeds   map[string]bool            // scope_id -> seed present
	inScope map[string]map[string]bool // scope_id -> set of in-scope claim ids

	// Verification material (SPEC §8.1), indexed by the subject it is about. Deliberately NOT part of
	// Record: its presence, absence or invalidity must not touch a record's validity or resolvability.
	material map[string][]VerificationMaterial

	// unresolved: scope_id -> count of PERSISTED claims that name this scope but do not resolve (their
	// prev/seed is missing). A non-zero count means the scope may be TRUNCATED - a withheld middle claim
	// leaves later claims (possibly the sealed head) unreachable, so the resolved tip is NOT necessarily
	// the real head. Surfaced by `head` so a truncation is never silent.
	unresolved map[string]int

	// deferred: claim id -> the record, for claims that are PERSISTED and offered to peers but kept
	// out of every index because their prev/seed has not arrived. Held-but-deferred is a THIRD state,
	// and it used to collapse into "not held": `show` and `verify` answered a deferred id with the
	// same message and the same exit code as a hash nobody has ever heard of. SPEC §12 makes the
	// distinction normative - "we do not have it" and "we have nothing about it" are different
	// answers, and a reader acts differently on each - and held-but-waiting is a third.
	//
	// Nothing new is tracked here that the kernel did not already know: these records are in `feed`
	// and counted in `deferredCount`. They are keyed by id so a LOOKUP can find them, which is the
	// one thing that was missing. They stay out of claimByID and every query index: a deferred claim
	// must not answer `about`/`by` as though its chain held.
	deferred map[string]Record

	// waiting: dependency id -> the deferred claims waiting for it. settleDeferred used to re-parse
	// and re-check EVERY deferred record on every pass, and Add calls it on every ingest - so m
	// pending records cost m envelope parses per Add, and the cascade that finally unblocks them
	// cost m². Measured: the single seed Add that unblocks a chain went 5ms -> 153ms at n=100 and
	// 566ms at n=200, doubling n quadrupling the time. `add` exists for bulk out-of-order federation
	// batches, where n is thousands.
	waiting map[string][]string

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
	if len(dirs) == 1 {
		return openAt(dirs[0], false)
	}

	// Every source's RAW records are collected first, then settled TOGETHER.
	//
	// This used to open dirs[0] normally - which SETTLED it alone and DROPPED whatever did not
	// resolve - and then settle only the remaining sources against that finished view. A scoped
	// child held in A whose seed lives in B was therefore dropped before B had even been read, and
	// reversing the argument order changed the answer: child_first=false, seed_first=true.
	// A union whose result depends on argument order is not a union, and §11-§12 promise a
	// conflict-free set union. Settling once over everything makes the operation commutative.
	u := newRegistry(dirs[0])
	var pending []Record
	for _, d := range dirs {
		objects := filepath.Join(d, "objects")
		if err := checkStoreFormat(d, objects); err != nil {
			return nil, err
		}
		recs, err := readStore(objects)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			rec.Seq = 0 // a source's own positions mean nothing in a union view; settle numbers them
			pending = append(pending, rec)
		}
		// Material is merged from EVERY source, and independently of settling. §8.1 says a record's
		// validity never depends on its material; the converse has to hold too - already-carried
		// evidence must not disappear because it happened to arrive in the second source.
		mergeMaterial(u.material, readAllMaterial(objects))
	}
	// A union's positions are SYNTHETIC: they are assigned per open, over whatever sources were
	// named, and belong to no store. So it gets a FRESH epoch each time, which is not a shortcut but
	// the honest answer: the epoch's contract is "if this changed, your cursor means nothing", and a
	// cursor against a union means nothing on the next open anyway. An EMPTY epoch would have been
	// neither "same" nor a usable "different" (SPEC §12).
	u.epoch = core.NewEpoch()
	u.dropped = u.settle(pending)
	if b, err := os.ReadFile(u.peersPath); err == nil {
		_ = json.Unmarshal(b, &u.peers)
	}
	return u, nil
}

// openAt loads a registry. create=false is the READ path (a peer being mirrored, or a --source): it
// never MkdirAll's the store - a read must not MUTATE the source it reads, and a read-only peer would
// otherwise fail the mkdir with "permission denied". A missing objects dir then reads as an empty
// registry.
// newRegistry allocates an EMPTY registry rooted at dir. Factored out of openAt so OpenUnion can
// build a union view without first loading - and silently settling - one of its sources.
func newRegistry(dir string) *Registry {
	return &Registry{
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
		deferred:    map[string]Record{},
		material:    map[string][]VerificationMaterial{},
		peers:       map[string]int{},
	}
}

// checkStoreFormat refuses a store this build cannot read. An unreadable store must never be
// mistaken for an empty one - a verification tool answering "nothing is recorded" where the truthful
// answer is "I cannot read this" is the most dangerous thing it can do.
func checkStoreFormat(dir, objectsDir string) error {
	format, err := readStoreFormat(objectsDir)
	if err != nil {
		return err
	}
	if format > StoreFormat {
		return fmt.Errorf("nekton store at %s is layout format %d, this build reads format %d.\n"+
			"Upgrade nekton instead of reading it with this build: an unreadable store must not be\n"+
			"mistaken for an empty one.", dir, format, StoreFormat)
	}
	return nil
}

// mergeMaterial folds src into dst, skipping an attachment dst already carries. Two sources holding
// the same evidence must not double it, and an UNKNOWN scheme is carried rather than filtered - the
// kernel evaluates no material (§8.1) and therefore cannot judge which schemes matter.
func mergeMaterial(dst, src map[string][]VerificationMaterial) {
	for subject, ms := range src {
		have := map[VerificationMaterial]bool{}
		for _, m := range dst[subject] {
			have[m] = true
		}
		for _, m := range ms {
			if have[m] {
				continue
			}
			have[m] = true
			dst[subject] = append(dst[subject], m)
		}
	}
}

func openAt(dir string, create bool) (*Registry, error) {
	r := newRegistry(dir)
	if create {
		if err := os.MkdirAll(r.objectsDir, 0o755); err != nil {
			return nil, err
		}
	}
	if err := checkStoreFormat(dir, r.objectsDir); err != nil {
		return nil, err
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
	// Number the records from objects/.seq BEFORE settling. Two things matter here. First, the
	// numbers come off disk, so a position already handed to a peer can never move. Second, the ids
	// are offered in readStore's stable store order rather than settle's RESOLUTION order - the
	// latter depends on what else is present, which is exactly how a planted record used to shift
	// everything after it.
	keys := make([]string, 0, len(pending))
	for _, rec := range pending {
		keys = append(keys, core.EnvelopeKey(rec.Envelope))
	}
	seqs, err := r.resolveSeqs(keys, create)
	if err != nil {
		return nil, err
	}
	for i := range pending {
		pending[i].Seq = seqs[core.EnvelopeKey(pending[i].Envelope)]
	}
	r.dropped = r.settle(pending)
	// Verification material is read AFTER settling and never feeds into it: §8.1 requires that its
	// presence, absence or invalidity leave a record's validity and resolvability untouched.
	r.material = readAllMaterial(r.objectsDir)
	if b, err := os.ReadFile(r.peersPath); err == nil {
		_ = json.Unmarshal(b, &r.peers)
	}
	return r, nil
}

// settle indexes records whose §7.4 chain resolves against the current state, repeating until a
// full pass adds nothing (a scoped child settles once its seed + prev are indexed), then drops
// the remainder as orphans / structurally-invalid. Used on replay so a planted or reordered
// on-disk object is not trusted, and reusable for out-of-order federation batches.
// positioned gives a record this store's own position if it does not already have one, and moves
// the cursor past it.
//
// EVERY record that enters the feed needs one. Records(since) answers `Seq > since`, so a Seq of 0 -
// which is what OpenUnion leaves on a foreign record, deliberately, because a number issued by
// another store means nothing here - is filtered out of every answer including Records(0). The
// assignment used to sit on one path only, and it also read `r.maxSeq + 1` without moving maxSeq:
// harmless where index() advanced it afterwards, a collision anywhere else.
func (r *Registry) positioned(rec Record) Record {
	if rec.Seq == 0 {
		r.maxSeq++
		rec.Seq = r.maxSeq
	}
	return rec
}

func (r *Registry) settle(pending []Record) (dropped int) {
	refused := 0
	for {
		progress := false
		var next []Record
		for _, rec := range pending {
			if r.seen[rec.ClaimID] {
				// A same-payload TWIN from another source. A claim id covers the PAYLOAD only, so two
				// independent signers of identical bytes are ONE claim with TWO signatures - which is
				// exactly what Add does at ingest. settle used to `continue` here, so reading A,B kept
				// only A's signer and reading B,A kept only B's: which co-signature survived depended
				// on argument order, and BySigner could not find the other one.
				r.mergeTwinInMemory(rec)
				// The line is in the STORE, so it is in the FEED. The index holds one unioned record
				// per claim id; the feed holds the lines that produced it, each with its own
				// position - that is what lets a peer past the original claim receive the
				// co-signature and union it for itself.
				//
				// POSITIONED first. This path does not reach index(), which is where a record's Seq
				// used to be settled, so a co-signature arriving through OpenUnion - which zeroes
				// foreign positions - kept Seq 0 and Records(since) filtered it out of every answer,
				// Records(0) included. Adding an empty source to a union was enough to stop the
				// public sync API delivering a signature the store still held.
				rec = r.positioned(rec)
				r.feed = append(r.feed, rec)
				continue
			}
			st, _, err := claim.ParseEnvelope(rec.Envelope)
			if err != nil {
				continue // unparseable → drop
			}
			p, _ := st.ParsePredicate()
			if err := r.checkChain(rec.ClaimID, st, p); err != nil {
				if errors.Is(err, errUnresolved) {
					next = append(next, rec) // INCOMPLETE, not invalid (§11) - defer to a later pass
				}
				// A structural violation is permanent: retrying it forever and then reporting it as
				// an unresolved dependency describes the wrong problem, and serving it to a peer
				// would hand on something we ourselves refuse.
				continue
			}
			rec = r.positioned(rec)
			// Only what the index ACCEPTS reaches the feed. Serving a peer a record this store
			// refuses hands on something we ourselves will not answer for, and the peer refuses it
			// in turn - an import that looks complete and is not. Counted as refused, which is a
			// different fact from deferred: one will never resolve, the other is still waiting.
			if !r.index(rec) {
				refused++
				progress = true // it is settled - permanently - so the loop has made progress
				continue
			}
			r.feed = append(r.feed, rec)
			progress = true
		}
		pending = next
		if !progress {
			// Whatever never resolved is a persisted-but-unreachable successor. Record the scope it names
			// so `head` can flag a possible TRUNCATION (a withheld middle claim), rather than silently
			// presenting the shortened chain's tip as the sealed head.
			for _, rec := range pending {
				if st, _, err := claim.ParseEnvelope(rec.Envelope); err == nil {
					var dep string
					if p, e := st.ParsePredicate(); e == nil && p != nil {
						if p.Scope != "" {
							if r.unresolved == nil {
								r.unresolved = map[string]int{}
							}
							r.unresolved[p.Scope]++
						}
						dep = waitsOn(p)
					}
					// Held, unresolvable, and still owed to a peer (see Records) - so it needs a
					// position like anything else in the feed, or it is owed and never delivered.
					rec = r.positioned(rec)
					r.feed = append(r.feed, rec)
					r.deferredCount++
					r.rememberDeferred(rec, dep)
				}
			}
			// Deferred and refused are both dropped from the INDEX, and they are not the same
			// thing: a deferred record may still resolve when its dependency arrives, a refused one
			// never will. Both are reported so a caller is not told everything arrived.
			return len(pending) + refused
		}
	}
}

// Unresolved reports how many persisted claims name this scope but do not resolve (a missing prev/seed)
// - a non-zero count means the scope may be TRUNCATED and its reported head is only provisional.
func (r *Registry) Unresolved(scope string) int { return r.unresolved[scope] }

// rememberDeferred records a persisted-but-unindexed claim so a lookup can find it. Called from both
// deferral sites - Add's and settle's - because a claim deferred at ingest and one deferred on replay
// are the same fact about this store, and a reader that could see only one of them would get a
// different answer before and after a restart.
func (r *Registry) rememberDeferred(rec Record, dep string) {
	if r.deferred == nil {
		r.deferred = map[string]Record{}
	}
	r.deferred[rec.ClaimID] = rec
	if dep != "" {
		if r.waiting == nil {
			r.waiting = map[string][]string{}
		}
		r.waiting[dep] = append(r.waiting[dep], rec.ClaimID)
	}
}

// waitsOn names the single record a deferred claim is waiting for: its `prev` if it has one, else
// the seed its scope names. Used only to retry the right records when that id arrives - a wrong or
// empty answer costs a retry that does not happen until the next arrival, never a wrong result,
// because settleDeferred re-checks the chain itself before promoting anything.
func waitsOn(p *claim.Predicate) string {
	if p == nil {
		return ""
	}
	if p.Prev != "" {
		return p.Prev
	}
	return p.Scope
}

// DeferredClaim reports a claim this registry HOLDS and offers to peers but has kept out of every
// index because its prev/seed has not arrived, together with the scope it is waiting on. (Deferred()
// below is the COUNT of such records - the two are named apart on purpose: a count answers "is this
// store complete", a lookup answers "what is the status of this id".)
//
// It is deliberately separate from Claim: a deferred claim must not answer `about`/`by` as though its
// chain resolved, and merging the two lookups would put it back into query results by the back door.
// What a caller gets is the ability to tell three states apart - not held, held and resolved, held
// and waiting - which SPEC §12 requires and which prose-parsing an error message is not.
func (r *Registry) DeferredClaim(id string) (rec Record, waitingOnScope string, ok bool) {
	rec, ok = r.deferred[id]
	if !ok {
		return Record{}, "", false
	}
	if st, _, err := claim.ParseEnvelope(rec.Envelope); err == nil && st != nil {
		if p, perr := st.ParsePredicate(); perr == nil && p != nil {
			// The scope it names is what it waits for; `prev` is the specific link, and a reader
			// that wants it has the envelope.
			waitingOnScope = p.Scope
		}
	}
	return rec, waitingOnScope, true
}

// index records + indexes a claim already assigned a seq (used during replay and after Add).
//
// It returns whether it ACCEPTED the record. It used to return nothing, so `settle` could not learn
// that indexing had refused one: the record went into the feed and progress was marked anyway, and
// `records --json` and the JSON export then republished claims this store itself will not serve. A
// receiving peer refuses them, so a source that looks usable delivers an incomplete import - and
// Dropped() did not count them, so the number said everything had arrived.
//
// A refusal is a record this store will not answer for. Already-held and envelope-unparseable are
// NOT refusals: in both the record is held, and the second is deliberately tolerated so one bad line
// cannot take a store's readable records with it.
func (r *Registry) index(rec Record) (accepted bool) {
	// SECURITY: RE-DERIVE the claim id from the envelope; never trust the on-disk claimId (or filename).
	// A planted file whose stored claimId equals a target's, but whose envelope is a different claim,
	// would otherwise SHADOW the real claim in bySubject/bySigner/byPredicate - so `nekton about`/`by`
	// answer "(none)" for a suppressed fail review. This is the check `Add` runs at ingest, missing on
	// the read path.
	st, payload, err := claim.ParseEnvelope(rec.Envelope)
	if err == nil && rec.ClaimID != "" {
		if derived := claim.ClaimID(payload); derived != rec.ClaimID {
			fmt.Fprintf(os.Stderr, "warning: skipping planted claim: stored id %s but its envelope derives %s\n", rec.ClaimID, derived)
			return false
		}
		// The rest of what Add enforces, applied HERE too. The read path re-derived the id
		// and stopped, so a claim Add refuses was fully indexed if it arrived by any other route -
		// and this package documents git merge as a supported federation transport, which bypasses
		// Add entirely. Concretely: the exact record the GATED `when-unvalidated` attack proves is
		// rejected - `"when":"whenever-you-like"` - was indexed and printed as an ordinary claim
		// once appended to a store file by hand. The PoC only ever exercised the CLI ingest path.
		if !rec.Envelope.HasSignature() {
			fmt.Fprintf(os.Stderr, "warning: skipping claim %s: it carries no signature (SPEC §8; Add refuses these at ingest)\n", rec.ClaimID)
			return false
		}
		if p, perr := st.ParsePredicate(); perr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping claim %s: %v\n", rec.ClaimID, perr)
			return false
		} else if verr := st.Validate(p); verr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping claim %s: %v\n", rec.ClaimID, verr)
			return false
		}
	}
	if r.seen[rec.ClaimID] {
		return true // already held; not a refusal
	}
	r.seen[rec.ClaimID] = true
	r.records = append(r.records, rec)
	if rec.Seq > r.maxSeq {
		r.maxSeq = rec.Seq
	}
	idx := len(r.records) - 1
	r.claimByID[rec.ClaimID] = rec
	if err != nil {
		return true // held, but nothing further to index from it
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
	return true
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

// mergeTwinInMemory unions a same-payload twin's signatures into the record already held, WITHOUT
// writing anything. settle runs on READ paths - replay and OpenUnion - and a read must never mutate
// the store it reads, least of all a peer's.
//
// unionSignatures still refuses to merge across DIFFERENT payload bytes (#93), so a record whose
// carried fields differ cannot have a signature attached to bytes its owner never signed. That
// prohibition is the point and is preserved here.
func (r *Registry) mergeTwinInMemory(rec Record) {
	old, ok := r.claimByID[rec.ClaimID]
	if !ok {
		return
	}
	merged, changed := unionSignatures(old.Envelope, rec.Envelope)
	if !changed {
		return
	}
	updated := Record{Seq: old.Seq, ClaimID: old.ClaimID, Envelope: merged}
	r.claimByID[rec.ClaimID] = updated
	for i := range r.records {
		if r.records[i].ClaimID == rec.ClaimID {
			r.records[i] = updated
			r.reindexSigners(i, old.Envelope, merged)
			break
		}
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
		// predicate/object, chain position) is unchanged; only the stored envelope's signature set grows.
		//
		// It is APPENDED as its own line, not written over the existing one. The subnekton is an
		// append-only log because in nekton the ORDER carries meaning (prev, head, seal) - rewriting
		// it in place erases the record of the change, which is precisely why no cursor could see it.
		// As its own line it gets its own position and is delivered like anything else.
		if old, ok := r.claimByID[id]; ok {
			merged, err := r.persistClaim(id, scopeOf(st, id), env)
			if err != nil {
				return "", false, fmt.Errorf("%w: %v", ErrPersist, err)
			}
			if core.EnvelopeKey(merged) == core.EnvelopeKey(old.Envelope) {
				return id, false, nil // nothing new: no line was written, so no position is issued
			}
			// The QUERY view keeps the record's own position - in a log where order means something,
			// an existing entry does not move. The FEED gains the co-signature at the end.
			rec := Record{Seq: old.Seq, ClaimID: id, Envelope: merged}
			r.claimByID[id] = rec
			for i := range r.records {
				if r.records[i].ClaimID == id {
					r.records[i] = rec
					r.reindexSigners(i, old.Envelope, merged)
					break
				}
			}
			seqs, serr := r.resolveSeqs([]string{core.EnvelopeKey(env)}, true)
			if serr != nil {
				return "", false, fmt.Errorf("%w: %v", ErrPersist, serr)
			}
			r.feed = append(r.feed, Record{Seq: seqs[core.EnvelopeKey(env)], ClaimID: id, Envelope: env})
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
		return "", false, fmt.Errorf("%w: %v", ErrPersist, err)
	}
	key := core.EnvelopeKey(merged)
	seqs, serr := r.resolveSeqs([]string{key}, true)
	if serr != nil {
		return "", false, fmt.Errorf("%w: %v", ErrPersist, serr)
	}
	rec := Record{Seq: seqs[key], ClaimID: id, Envelope: merged}
	if chainErr != nil { // errUnresolved: persisted, awaiting its dependency
		// IDEMPOTENT per claim id. A deferred claim is not in `r.seen` - it never reached the index -
		// so the twin path above does not catch a re-add, and this branch used to count it again
		// EVERY time. Adding the same deferred claim twice gave Deferred()=2 and Unresolved=2 for
		// one record, appended a second feed entry so `Records(cursor)` delivered it twice, and left
		// both counters stuck above zero once it resolved: `head` then reports a truncation that is
		// not there, and export's `deferred` count is wrong. Only a reopen cleared it.
		if _, already := r.deferred[id]; already {
			return id, false, nil
		}
		if p != nil && p.Scope != "" {
			r.unresolved[p.Scope]++ // may be a withheld-middle successor -> `head` flags a truncation
		}
		// Out of every index, but IN the feed: a peer must be offered what we hold (see Records).
		r.feed = append(r.feed, rec)
		r.deferredCount++
		r.rememberDeferred(rec, waitsOn(p))
		return id, true, nil
	}
	// Only what the index ACCEPTS reaches the feed. `index` already returned this - settle has
	// honoured it since #161 - and here the answer was DISCARDED, so a record the index refused was
	// appended anyway and served to peers. What a peer then received was a false id -> claim
	// binding: it refuses the record in turn, so an import that looks complete is not, which is
	// exactly the defect #149 was filed for on the half that stayed open.
	//
	// HONESTLY: with persistClaim's identity check in place this branch is UNREACHABLE through Add.
	// `merged` is now either `env` itself or a union of envelopes that all derive this id, and every
	// other thing index refuses - no signature, unparseable predicate, failed Validate - Add has
	// already rejected above. Removing this gate does not fail the regression beside it, and saying
	// otherwise would be the kind of claim this repository keeps having to retract.
	//
	// It stays because it is where the invariant is ENFORCED rather than merely currently true: the
	// feed must never carry a record the index will not answer for, and the next person to change
	// what persistence returns should hit a refusal, not a silently republished false binding.
	//
	// (The twin branch above appends the INCOMING envelope, whose id was derived from its own
	// payload a few lines up, so it is self-consistent by construction and needs no gate.)
	if !r.index(rec) {
		return "", false, fmt.Errorf("claim %s was refused by the index and has not been stored - "+
			"see the warning above for which check it failed", id)
	}
	r.feed = append(r.feed, rec)
	// This record may be the dependency something already held has been waiting for. `Add` used to
	// leave those alone, so within ONE process adding a seed did not resolve the scoped claim that
	// named it:
	//
	//     add the scoped claim   -> indexed=false deferred=true
	//     add its seed           -> indexed=false deferred=true   <- still
	//     reopen                 -> indexed=true  deferred=false
	//
	// The CLI hid it, because the next command reopens. A LINKED consumer - which is what the
	// registry methods and the template package were extracted for - saw a claim that never
	// resolved, with no way to tell that reopening would fix it. It also made `add`'s own summary
	// wrong and order-dependent: "indexed 2 claims, 0 refused (registry now holds 1)".
	r.settleDeferred(id)
	return id, true, nil
}

// settleDeferred retries every held-but-deferred record against the current index, repeating while
// anything resolves - one arrival can unblock a chain, and unblocking a link can unblock the next.
//
// It only ever MOVES a record from deferred to indexed. Nothing is persisted (the records are
// already on disk), nothing is appended to the feed (they were offered when they arrived, and a
// second entry would deliver them twice), and a record that still does not resolve stays exactly as
// it was. So calling it cannot lose work, and calling it when nothing is pending costs one map
// length check.
func (r *Registry) settleDeferred(arrived string) {
	// Retry only what was waiting for THIS id, then what was waiting for each record that just
	// resolved. Scanning the whole deferred set instead re-parsed every pending envelope on every
	// ingest, so m pending records cost m parses per Add and the unblocking cascade cost m².
	queue := []string{arrived}
	for len(queue) > 0 {
		dep := queue[0]
		queue = queue[1:]
		ids := r.waiting[dep]
		if len(ids) == 0 {
			continue
		}
		delete(r.waiting, dep)
		for _, id := range ids {
			rec, held := r.deferred[id]
			if !held {
				continue // already settled by another path
			}
			st, _, err := claim.ParseEnvelope(rec.Envelope)
			if err != nil {
				continue // unparseable: it was never going to resolve
			}
			p, perr := st.ParsePredicate()
			if perr != nil {
				continue
			}
			// The chain is re-checked here, so an imprecise `waitsOn` can only cost a retry that
			// happens later - never a record promoted before its dependency is actually present.
			if cerr := r.checkChain(id, st, p); cerr != nil {
				// Still waiting. Put it back under the dependency it names now, or it would never be
				// retried again: the index entry was consumed above.
				r.rememberDeferred(rec, waitsOn(p))
				continue
			}
			if !r.index(rec) {
				continue
			}
			delete(r.deferred, id)
			r.deferredCount--
			if p.Scope != "" && r.unresolved[p.Scope] > 0 {
				r.unresolved[p.Scope]--
			}
			// Whatever was waiting for THIS record can now be tried.
			queue = append(queue, id)
		}
	}
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
	// The context-free half of §7.4 lives in the claim package, called from here AND from `verify`.
	// Defined once on purpose: `verify` never reaches a registry, so a copy of these rules here is
	// how the two commands come to disagree about what a storable record is.
	if err := claim.ValidateChainStructure(st, p); err != nil {
		return err
	}
	if st.IsSeed() {
		return nil // the rest of §7.4 for a seed is context-free and already checked above
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

// ErrPersist wraps a LOCAL persistence failure - the disk, the path, the lock - as opposed to
// anything wrong with the record. The distinction is the whole point: a caller must be able to tell
// "this claim is invalid, skip it" from "I could not write, nothing was stored".
//
// Without it, `nekton mirror` classified every Add error as a retryable missing dependency and, after
// retrying it pointlessly, reported a write failure as "1 unresolved (missing dependency - an
// incomplete chain)" with exit 0. It was not a dependency problem and the chain was not
// incomplete. Mirrors that report success while storing nothing are the worst possible outcome
// for a tool whose job is evidence.
//
// Mirrors plankton's registry.ErrPersist, deliberately: both kernels are asked the same question by
// the same callers.
var ErrPersist = errors.New("failed to persist claim locally")

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

// seqFileName is the store-local federation numbering (SPEC §12). It sits NEXT TO peers.json, not
// inside objects/: it has exactly peers.json's character - local bookkeeping about federation, not
// content - and keeping it out of objects/ means the record tree a git federation ships stays
// records only, with nothing in it that two stores would legitimately disagree about.
const seqFileName = ".seq"

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
//	objects/scope/<scope_id>.material.jsonl  verification material about its claims (SPEC §8.1)
//	objects/unscoped.nekton.jsonl            the unscoped nekton
//	objects/unscoped.material.jsonl          verification material about unscoped claims
//
// A scope is a bounded, federatable sub-registry (seed.go), and this gives it one artifact: a thing
// that can be chmod'd, sparse-checked-out, copied, or handed over whole - none of which a flat pile
// of per-claim hashes can be. The file is a BAG, not a sequence: order stays the chain's alone
// (`prev`), so the file never becomes a second, unsigned representation of order that could drift
// from the signed one. JSONL so a new claim is an append, not a rewrite of the subnekton.
func subnektonPath(objectsDir, scope string) (string, error) {
	if scope == "" {
		return filepath.Join(objectsDir, "unscoped.nekton.jsonl"), nil
	}
	// `scope` comes out of a SIGNED CLAIM PAYLOAD and is attacker-chosen: any party with any key can
	// put any string there, and ingest does not verify signatures (SPEC §8). Deriving a filesystem
	// path from it unvalidated let a claim carrying `scope: "sha256:../../../tmp/x"` create and
	// append to a file anywhere the process could write - and, on a second ingest of the same claim,
	// rewriteSubnekton truncated that file to the attacker's record. A hostile peer reached this
	// through `kton mirror`, which feeds peer envelopes straight to Add.
	//
	// Same class as the blobstore path (#79), fixed there and left here. So: the scope must be a
	// canonical content hash before it can name a file, and the result is proven to stay under the
	// store root as defence in depth.
	return scopedPath(objectsDir, scope, ".nekton.jsonl")
}

// scopedPath is the ONE place a scope becomes a filename, for records and for their verification
// material alike. Both derive from the same attacker-chosen field, so both are guarded here rather
// than in two places that could drift.
func scopedPath(objectsDir, scope, suffix string) (string, error) {
	norm, ok := core.NormalizeContentHash(scope)
	if !ok {
		return "", fmt.Errorf("scope %q is not a sha256 content hash; refusing to derive a store path from it", scope)
	}
	_, hex := splitID(norm)
	path := filepath.Join(objectsDir, "scope", hex+suffix)
	root, err := filepath.Abs(objectsDir)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing a store path outside the root (scope %q)", scope)
	}
	return path, nil
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
// costs one line, never N.
//
// A crash mid-append leaves a TORN final line with no newline. That line is lost, which is correct -
// it was never acknowledged. What is NOT acceptable is what used to happen to the record after it:
// an O_APPEND write lands directly on the torn line, concatenating the two, so the reader discards
// BOTH. `Add` had already returned success and indexed the claim, and it was gone on the next open -
// an acknowledged write lost to somebody else's interrupted one.
//
// So the tail is isolated first: a lone newline turns the torn fragment into a line of its own,
// which the reader skips with a warning, and the new record starts clean. Written in ONE call
// together with the record, so this repair cannot itself be interrupted halfway.
func appendSubnekton(path string, of objectFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	line, err := marshalRecord(of)
	if err != nil {
		return err
	}
	torn, err := hasTornTail(path)
	if err != nil {
		return err
	}
	if torn {
		line = append([]byte{'\n'}, line...)
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

// hasTornTail reports whether path ends in a partial line - content not terminated by a newline.
// An empty or absent file is not torn. A read error is NOT reported as "not torn": appending onto a
// file we could not inspect is how the record after a torn one was lost in the first place.
func hasTornTail(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Size() == 0 {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], fi.Size()-1); err != nil {
		return false, err
	}
	return b[0] != '\n', nil
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

// Records answers §12's sync(since): everything this participant holds above the cursor, in
// sequence order.
//
// DEFERRED records are included, and that is the point. A claim whose seed or prev is not held here
// is persisted and structurally valid - incomplete is not invalid (SPEC §11) - but it used to be
// absent from `records` and therefore from the feed, so a peer NEVER RECEIVED IT AT ALL. When the
// missing dependency later arrived and the claim resolved locally, it entered the indexed set at its
// ORIGINAL position, below every cursor already issued, and was never delivered either.
// The feed was hiding a record the store was holding.
//
// Offering it is safe in exactly the sense §11 gives: federation is monotone, so handing a peer more
// signed, structurally valid records can only add to what it can conclude. The peer defers it too,
// and resolves it when it gets the dependency - the same thing we do. Withholding it is what loses
// information.
func (r *Registry) Records(since int) []Record {
	var out []Record
	for _, rec := range r.feed {
		if rec.Seq > since {
			out = append(out, rec)
		}
	}
	return out
}

// Deferred reports how many held records are still waiting for a dependency. They are served to
// peers but answer no query here.
func (r *Registry) Deferred() int { return r.deferredCount }

// MaxSeq is the current local cursor.
// Epoch identifies the numbering a cursor belongs to. A peer whose stored epoch differs from the one
// in an answer MUST discard its cursor and resync from zero: the positions it holds were issued by a
// numbering that no longer exists, and it would otherwise sit silently above everything it is
// offered. See core.SeqMap.
func (r *Registry) Epoch() string { return r.epoch }

// MaxSeq is the cursor to hand back: the highest position in the FEED, not in the index.
//
// It used to come from the index, so a co-signature - which has a position but answers no query of
// its own - was returned by Records(since) and then NOT covered by the cursor that came with it. The
// peer would have stored the old cursor and been handed the same co-signature on every subsequent
// sync, forever. Losing a record is worse than repeating one, but a cursor that does not cover what
// was just delivered is simply not a cursor.
func (r *Registry) MaxSeq() int {
	max := r.maxSeq
	for _, f := range r.feed {
		if f.Seq > max {
			max = f.Seq
		}
	}
	return max
}

// derivesClaimID reports whether env's payload actually hashes to id. A claim id is
// sha256(canon(Statement)) - the payload digest exactly - so this is the whole test, and an envelope
// that fails it is not the claim it is filed under whatever the surrounding `claimId` field says.
//
// An unparseable envelope fails too, deliberately: its signatures stand over bytes we cannot
// identify, so they are not evidence about this record.
func derivesClaimID(env core.Envelope, id string) bool {
	_, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return false
	}
	return claim.ClaimID(payload) == id
}

// Len reports the number of indexed claims.
func (r *Registry) Len() int { return len(r.claimByID) }

// PeerCursor / SetPeerCursor track replication progress against a peer.
func (r *Registry) PeerCursor(url string) int { return r.peers[url] }

// SetPeerCursor records and persists the last remote seq pulled from a peer.
func (r *Registry) SetPeerCursor(url string, seq int) error {
	r.peers[url] = seq
	// peers.json is ONE file every mirror mutates, so two concurrent mirrors would otherwise lose one
	// another's cursor - and a lost cursor is a silently re-fetched or silently SKIPPED range. Merged
	// by MAXIMUM under the lock, never clobbered: a cursor only ever moves forward, so the later
	// writer's view of a peer it did not talk to must not roll that peer back. plankton got this in
	// #77; nekton kept the plain read-modify-write until now.
	return r.withWriteLock(func() error {
		on := map[string]int{}
		if b, err := os.ReadFile(r.peersPath); err == nil {
			_ = json.Unmarshal(b, &on)
		}
		for k, v := range r.peers {
			if v > on[k] {
				on[k] = v
			}
		}
		for k, v := range on {
			r.peers[k] = v
		}
		b, err := json.MarshalIndent(on, "", "  ")
		if err != nil {
			return err
		}
		return atomicWrite(r.peersPath, b)
	})
}

// materialPath is where evidence about a subnekton's claims lives: one JSONL file BESIDE the
// subnekton, never inside it (SPEC §8.1, #62).
//
//	objects/scope/<scope_id>.nekton.jsonl      the subnekton
//	objects/scope/<scope_id>.material.jsonl    verification material about its claims
//
// Beside, for three reasons that only a separate file satisfies together. A material file that
// cannot be read cannot break a record read, which is what §8.1 requires. `cp objects/scope/<id>.*`
// still hands a scope over whole, which is what #41 is for. And ".material.jsonl" matches neither
// ".nekton.jsonl" nor ".json", so a build that does not know about it ignores the file entirely
// rather than parsing records and dropping fields.
//
// That last one decided it. persistClaim rewrites the WHOLE subnekton file through
// objectFile{ClaimID, Envelope} on every co-signature merge, so material carried as a field on that
// struct would be erased for every record in the file by any older build that co-signed one claim -
// silently, reporting success. That is the failure mode 0.2 exists to document.
func materialPath(objectsDir, scope string) (string, error) {
	if scope == "" {
		return filepath.Join(objectsDir, "unscoped.material.jsonl"), nil
	}
	return scopedPath(objectsDir, scope, ".material.jsonl")
}

// readMaterialFile parses one material file. Tolerant in the same way readSubnekton is: one corrupt
// line must not hide the rest, and must never affect the records the file is about.
func readMaterialFile(path string) []VerificationMaterial {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []VerificationMaterial
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var vm VerificationMaterial
		if err := json.Unmarshal([]byte(line), &vm); err != nil || vm.Subject == "" {
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable verification material in %s\n", path)
			continue
		}
		out = append(out, vm)
	}
	// A scanner stops on the FIRST error and reports it only here. Without this check, one line
	// longer than the buffer ends the loop silently and every attachment AFTER it disappears with no
	// warning - the file reads as if it simply ended. §8.1 says material must never affect a
	// record's validity, and it does not; but losing evidence quietly is exactly the failure this
	// substrate exists to prevent, so say it.
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: verification material in %s is INCOMPLETE - stopped reading at %v\n", path, err)
	}
	return out
}

// readAllMaterial indexes every material file under objectsDir by the subject it is about.
func readAllMaterial(objectsDir string) map[string][]VerificationMaterial {
	out := map[string][]VerificationMaterial{}
	var paths []string
	_ = filepath.WalkDir(objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a missing objects dir reads as no material, never as an error
		}
		if !d.IsDir() && strings.HasSuffix(p, ".material.jsonl") {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	for _, p := range paths {
		for _, vm := range readMaterialFile(p) {
			out[vm.Subject] = append(out[vm.Subject], vm)
		}
	}
	return out
}

// Material returns the verification material recorded about a subject, in the order it was
// attached. The kernel does not evaluate any of it (SPEC §8.1, §15).
func (r *Registry) Material(subject string) []VerificationMaterial { return r.material[subject] }

// AttachMaterial records evidence about a claim already in this registry. It is stored beside the
// claim's own subnekton, so handing over a scope hands over its evidence too.
//
// It deliberately does NOT verify Material, and does not care whether Scheme is one it has heard of:
// refusing unknown evidence would make the set of schemes a protocol version, which is precisely
// what §8.1 exists to avoid.
func (r *Registry) AttachMaterial(vm VerificationMaterial) error {
	if vm.Subject == "" || vm.Scheme == "" || vm.Material == "" {
		return fmt.Errorf("verification material needs subject, scheme and material")
	}
	rec, ok := r.claimByID[vm.Subject]
	if !ok {
		// A DEFERRED claim is held too, just not indexed - its prev/seed has not arrived (SPEC §11:
		// incomplete, not invalid). Refusing to attach evidence to it would make external evidence
		// depend on chain completeness, which §8.1 says it must not: a record's validity never
		// depends on its material, and the converse has to hold or a proof cannot be filed until an
		// unrelated predecessor turns up. The binding is safe regardless - a claim id IS the payload
		// hash, so the material names these exact bytes.
		rec, _, ok = r.DeferredClaim(vm.Subject)
	}
	if !ok {
		return fmt.Errorf("no claim %s in this registry - material binds to a record's content address, not to a file", vm.Subject)
	}
	st, _, err := claim.ParseEnvelope(rec.Envelope)
	if err != nil {
		return err
	}
	path, perr := materialPath(r.objectsDir, scopeOf(st, vm.Subject))
	if perr != nil {
		return perr
	}
	err = r.withWriteLock(func() error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		b, err := json.Marshal(vm)
		if err != nil {
			return err
		}
		// Isolate a TORN TAIL, exactly as appendSubnekton does. A crash mid-append leaves an
		// unterminated line; a bare O_APPEND write then lands directly on it, concatenating the two,
		// and the reader discards BOTH - so an acknowledged attach is lost to somebody else's
		// interrupted one. #143 fixed this for records and did not reach the material writers, which
		// have the identical failure mode. Material is the evidence a proof is filed under, so
		// losing it silently is how an anchored record ends up with nothing to show.
		//
		// The newline is written in the SAME call as the content, so there is no window in which a
		// line exists without its terminator.
		torn, terr := hasTornTail(path)
		if terr != nil {
			return terr
		}
		line := append(b, '\n')
		if torn {
			line = append([]byte{'\n'}, line...)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(line)
		return err
	})
	if err != nil {
		return err
	}
	r.material[vm.Subject] = append(r.material[vm.Subject], vm)
	return nil
}

// ClaimIDs returns every claim id this registry holds, in a stable order. Used by the material pull
// (kton mirror --with-material), which asks the peer about every record held rather than about the
// last sync batch - material is attached out of band and after the fact, so a batch would miss it.
func (r *Registry) ClaimIDs() []string {
	out := make([]string, 0, len(r.claimByID))
	for id := range r.claimByID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
