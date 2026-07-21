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

// readObjectEnvelope reads the CURRENT on-disk envelope for a claim id (the source of truth under the
// write lock), so a co-signature merge unions against what another process may have just written, not a
// stale in-memory copy.
func (r *Registry) readObjectEnvelope(id string) (core.Envelope, bool) {
	b, err := os.ReadFile(objectPath(r.objectsDir, id))
	if err != nil {
		return core.Envelope{}, false
	}
	var of objectFile
	if json.Unmarshal(b, &of) != nil {
		return core.Envelope{}, false
	}
	return of.Envelope, true
}

// persistClaim writes a claim object as a LOCKED on-disk read-modify-write: under the write lock it
// unions the incoming signatures with whatever is already on disk (possibly just written by another
// process), then atomic-writes. This makes ALL persists of a claim id safe - whether or not this
// process had yet SEEN the claim - so N processes co-signing the same statement concurrently never
// clobber each other (every co-signature survives). Returns the merged envelope actually stored.
func (r *Registry) persistClaim(id string, env core.Envelope) (core.Envelope, error) {
	merged := env
	err := r.withWriteLock(func() error {
		if disk, ok := r.readObjectEnvelope(id); ok {
			m, _ := unionSignatures(disk, env)
			merged = m
		}
		return r.writeObject(id, Record{ClaimID: id, Envelope: merged})
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
func Open(dir string) (*Registry, error) {
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
	if err := os.MkdirAll(r.objectsDir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	if err := filepath.WalkDir(r.objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			paths = append(paths, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var pending []Record
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var of objectFile
		if err := json.Unmarshal(b, &of); err != nil {
			// A single corrupt/truncated object MUST NOT disable reads over every other (good)
			// record - one bad byte would otherwise be a registry-wide DoS. Skip it, name it on
			// stderr, keep going.
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable record %s: %v\n", p, err)
			continue
		}
		pending = append(pending, Record{ClaimID: of.ClaimID, Envelope: of.Envelope})
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
			merged, err := r.persistClaim(id, env)
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
	merged, err := r.persistClaim(id, env)
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

func objectPath(objectsDir, claimID string) string {
	algo, h := "sha256", claimID
	if i := strings.IndexByte(claimID, ':'); i >= 0 {
		algo, h = claimID[:i], claimID[i+1:]
	}
	return filepath.Join(objectsDir, algo, h+".json")
}

func (r *Registry) writeObject(claimID string, rec Record) error {
	p := objectPath(r.objectsDir, claimID)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(objectFile{ClaimID: rec.ClaimID, Envelope: rec.Envelope}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
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
	var out []Record
	_ = filepath.WalkDir(r.objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		var of objectFile
		if json.Unmarshal(b, &of) == nil {
			out = append(out, Record{ClaimID: of.ClaimID, Envelope: of.Envelope})
		}
		return nil
	})
	return out
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
