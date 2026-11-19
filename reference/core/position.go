package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Position is a cheap answer to "did anything in this store change since I last looked?" (#233),
// for an index that follows a registry directory and wants to skip a full Open when nothing did.
//
// It is read without opening the store: no replay, no settle, no lock, no parse of a record. Two
// positions that are equal mean nothing changed; any difference means "open it and find out".
//
// MaxSeq alone would not do. A record can reach objects/ without being numbered - by a git merge,
// which both layers document as a federation transport and which bypasses Add, or through a
// read-only open, which numbers in memory and writes nothing - and it gets its position only when a
// writer next opens the store. A position read from .seq alone would then say "unchanged" exactly
// when something arrived. Objects covers that: it changes whenever a record or material file is
// added, appended to or replaced, numbered or not.
type Position struct {
	// Epoch is the numbering a cursor belongs to (SeqMap.Epoch), or "" when the store has no numbering
	// yet. A consumer whose stored epoch differs re-reads from 0.
	Epoch string `json:"epoch"`
	// MaxSeq is the highest position the numbering has handed out. Informational: it may lag the
	// records on disk (see above).
	MaxSeq int `json:"maxSeq"`
	// Objects is sha256 over the sorted (relative path, size, modification time) of every file under
	// objects/ that Open could read: dot names included, a symlink by its target, as Open reads it.
	// Only the format marker objects/.format is left out; the rest of the bookkeeping (.seq,
	// peers.json, locks) lives outside objects/ and never changes it.
	Objects string `json:"objects"`
	// Held is an order-independent digest of the set of record keys the store holds on disk: the XOR
	// of sha256(key) over every distinct key, 64 hex digits (#260). It is computed without opening the
	// store - a plankton key is an object file's name, a nekton key is each line's claimId, read but
	// neither parsed further nor verified. Because XOR is its own inverse, a consumer can keep its own
	// copy current: start from the Held it last read and HeldWith(held, key) for every key that
	// Records(since) brings that it did not hold. If the next Position.Held differs from that, the
	// store lost something (a checkout or merge from outside: the kernel never removes), and the
	// consumer reads again from 0. Co-signatures and twins share their key, so they never change it.
	//
	// A key counts only where the content proves it (#261 review H1): a nekton line whose payload hashes
	// to its claimId, a plankton object file whose record derives the file's name. So a stray file or a
	// claimId-only line does not count, nor does a record without any signature (Add's own minimum;
	// Records never delivers one, so counting it made a consumer re-read for ever). Held detects LOSS - a checkout or merge that dropped records - not
	// a forger: XOR is linear, and whoever can write the store can plant records that cancel a removal
	// (and could as well rewrite .seq and its epoch). A multiset hash (MuHash, LtHash) would be the step
	// up if that ever has to hold.
	Held string `json:"held"`
}

// HeldWith returns held with key toggled in: the incremental form of Position.Held. held "" is the
// empty set.
func HeldWith(held, key string) string {
	var acc [32]byte
	if b, err := hex.DecodeString(held); err == nil && len(b) == 32 {
		copy(acc[:], b)
	}
	sum := sha256.Sum256([]byte(key))
	for i := range acc {
		acc[i] ^= sum[i]
	}
	return hex.EncodeToString(acc[:])
}

// heldKeys returns the record keys behind one file under objects/, by its name (rel, slash form) and,
// for a nekton subnekton file, its lines: <algo>/<hex>.json is the record <algo>:<hex>; a
// *.nekton.jsonl line contributes its claimId. Anything else (material, markers, temp files) holds
// no record.
func heldKeys(path, rel string) []string {
	if strings.HasSuffix(rel, ".nekton.jsonl") {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var keys []string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var of struct {
				ClaimID  string   `json:"claimId"`
				Envelope Envelope `json:"envelope"`
			}
			if json.Unmarshal([]byte(line), &of) != nil || of.ClaimID == "" {
				continue
			}
			if len(of.Envelope.Signatures) == 0 {
				continue // Add's own minimum: a claim is constituted by its signature
			}
			if pb, err := of.Envelope.PayloadBytes(); err == nil && HashBytes(pb) == of.ClaimID {
				keys = append(keys, of.ClaimID)
			}
		}
		return keys
	}
	parts := strings.Split(rel, "/")
	if len(parts) == 2 && strings.HasSuffix(parts[1], ".json") && !strings.HasPrefix(parts[1], ".") {
		key := parts[0] + ":" + strings.TrimSuffix(parts[1], ".json")
		if objectProvesKey(path, key) {
			return []string{key}
		}
	}
	return nil
}

// objectProvesKey reports whether a plankton object file's record derives its own file name: its foton
// id (computed, not the stored field) or, for a record with none, the hash of its payload - the key the
// registry filed it under - and that carries at least one signature, as Add requires. No signature is
// verified; this only keeps non-records out of Held.
func objectProvesKey(path, key string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var of struct {
		FotonID  string   `json:"fotonId"`
		Envelope Envelope `json:"envelope"`
	}
	if json.Unmarshal(b, &of) != nil || len(of.Envelope.Signatures) == 0 {
		return false
	}
	if of.FotonID == "" {
		pb, err := of.Envelope.PayloadBytes()
		return err == nil && HashBytes(pb) == key
	}
	st, err := of.Envelope.Statement()
	if err != nil {
		return false
	}
	f, err := st.ToFoton()
	if err != nil {
		return false
	}
	id, err := f.FotonID()
	return err == nil && id == of.FotonID && id == key
}

// ReadPosition reads the position of the store at dir (a plankton or nekton registry directory).
//
// A consumer reads the position BEFORE it reads records (Records(since) / `records --since`), so a
// record that lands in between shows up as a change next time rather than being stamped as seen.
// Equal positions mean nothing changed. Otherwise: open the store; if Epoch differs, re-read from 0;
// if Objects changed but MaxSeq did not, re-read from 0 as well - those are records nobody has
// numbered yet (a git merge into a store no writer has opened since), and the positions a read-only
// Open gives them exist only in that process's memory, so a cursor cannot be kept against them.
//
// Not covered: a file replaced by different bytes of the same size and modification time. Records
// are content-addressed and append-only, so that is the same content or tampering, and tampering is
// verification's job, not a change detector's.
func ReadPosition(dir string) (Position, error) {
	var p Position
	if b, err := os.ReadFile(filepath.Join(dir, ".seq")); err == nil {
		// Read the two fields directly. ReadSeqMap invents a fresh epoch for a file without one, which
		// would make every call report "changed".
		var m struct {
			Epoch string `json:"epoch"`
			Next  int    `json:"next"`
		}
		if json.Unmarshal(b, &m) == nil {
			p.Epoch = m.Epoch
			if m.Next > 1 {
				p.MaxSeq = m.Next - 1
			}
		}
	} else if !os.IsNotExist(err) {
		return Position{}, err
	}
	objects := filepath.Join(dir, "objects")
	var lines []string
	held := map[string]bool{}
	err := filepath.WalkDir(objects, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == objects {
				return fs.SkipAll // no objects/ yet: an empty store
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(objects, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".format" {
			return nil
		}
		// Every other file counts, whatever its name, because Open does not filter by name either: a
		// record under a dot path or behind a symlink is read, so it has to move the position. A
		// symlink is taken by its target, as Open reads it (os.Stat follows it); a dangling one is
		// still a fact about the tree.
		info, err := os.Stat(path)
		if err != nil {
			lines = append(lines, rel+"\x00dangling")
			return nil
		}
		lines = append(lines, fmt.Sprintf("%s\x00%d\x00%d", rel, info.Size(), info.ModTime().UnixNano()))
		for _, k := range heldKeys(path, rel) {
			held[k] = true
		}
		return nil
	})
	if err != nil {
		return Position{}, err
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	p.Objects = "sha256:" + hex.EncodeToString(sum[:])
	for k := range held {
		p.Held = HeldWith(p.Held, k)
	}
	if p.Held == "" {
		p.Held = hex.EncodeToString(make([]byte, 32))
	}
	return p, nil
}
