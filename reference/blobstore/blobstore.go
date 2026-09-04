// Package blobstore is an OPTIONAL content-addressed byte store. The plankton kernel
// (registry) stores no bytes (spec §6.1, §10); this is a separate, opt-in backend used only
// for *pinning* - fetching the bytes behind a hash, verifying them, and re-serving them
// (the uri-rot defence / GxP retention; spec §7 F13.8). Files are stored by content hash,
// sharded by the first hash byte.
package blobstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kton.dev/plankton/core"
)

// Subdir is where a registry's pinned bytes live, relative to the registry directory. It used to be
// defined in the kton cockpit's federation package - so plankton's own storage layout was declared
// in a package that depends on plankton. It belongs here, with the bytes.
const Subdir = "blobs"

// OpenFor opens the blob store belonging to a registry directory. Every caller derived this path by
// hand; one of them getting it wrong would silently pin into a store nothing else reads.
func OpenFor(registryDir string) (*Store, error) {
	return Open(filepath.Join(registryDir, Subdir))
}

// Store is a content-addressed byte store rooted at a directory.
type Store struct{ dir string }

// Open creates/opens a blob store.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// path maps a content hash to its file. It NEVER derives a path from an unvalidated string.
//
// It used to check only the length, so any 64 characters reached filepath.Join - and 64 characters
// can contain separators and "..", which Join then normalises away. os.ReadFile ran on the result
// BEFORE the hash comparison that would have rejected it, and /blob?hash= feeds a query parameter
// straight in, unauthenticated. The mismatch still stopped the bytes being returned as a blob, so
// this was never byte disclosure - it was an existence-and-timing oracle and a way to pull an
// arbitrary large file into memory (AUD-04).
//
// core.NormalizeContentHash already enforces exactly the right thing: canonical lowercase hex of a
// 32-byte digest, prefix optional and case-insensitive. Anything else stops here.
func (s *Store) path(hash string) (string, error) {
	norm, ok := core.NormalizeContentHash(hash)
	if !ok {
		return "", fmt.Errorf("not a sha256 content hash: %q", hash)
	}
	hx := strings.TrimPrefix(norm, "sha256:")
	p := filepath.Join(s.dir, hx[:2], hx)
	// Defence in depth: the normalizer already makes escaping impossible, but a path derived from
	// input should be proven to stay under its root rather than assumed to.
	root, err := filepath.Abs(s.dir)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing a blob path outside the store root: %q", hash)
	}
	return p, nil
}

// Has reports whether the content for hash is stored.
func (s *Store) Has(hash string) bool {
	p, err := s.path(hash)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Get returns the stored bytes for hash (and re-verifies them on read).
func (s *Store) Get(hash string) ([]byte, error) {
	p, err := s.path(hash)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	// Compare against the CANONICAL form, not the caller's spelling. HashBytes always returns
	// "sha256:<lowerhex>", so comparing to a bare or uppercase argument made a blob that had just
	// been found on disk report itself corrupt - the hash-split failure NormalizeContentHash exists
	// to prevent, reached through the one path that had not been routed through it (AUD-04 sibling).
	want, _ := core.NormalizeContentHash(hash)
	if got := core.HashBytes(b); got != want {
		return nil, fmt.Errorf("blob corrupt: stored %s but content is %s", want, got)
	}
	return b, nil
}

// PutVerified stores b only if its content hash equals expected (trust the hash, not the
// source). This is the verify-on-receipt used by pinning.
func (s *Store) PutVerified(expected string, b []byte) error {
	want, ok := core.NormalizeContentHash(expected)
	if !ok {
		return fmt.Errorf("not a sha256 content hash: %q", expected)
	}
	if got := core.HashBytes(b); got != want {
		return fmt.Errorf("hash mismatch: expected %s, got %s", want, got)
	}
	p, err := s.path(expected)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// Put stores b under its own content hash and returns that hash.
func (s *Store) Put(b []byte) (string, error) {
	h := core.HashBytes(b)
	return h, s.PutVerified(h, b)
}
