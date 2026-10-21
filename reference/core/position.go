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
		return nil
	})
	if err != nil {
		return Position{}, err
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	p.Objects = "sha256:" + hex.EncodeToString(sum[:])
	return p, nil
}
