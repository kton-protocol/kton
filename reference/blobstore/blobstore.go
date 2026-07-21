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

// Store is a content-addressed byte store rooted at a directory.
type Store struct{ dir string }

// Open creates/opens a blob store.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(hash string) (string, error) {
	hx := strings.TrimPrefix(hash, "sha256:")
	if len(hx) != 64 {
		return "", fmt.Errorf("not a sha256 hash: %q", hash)
	}
	return filepath.Join(s.dir, hx[:2], hx), nil
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
	if got := core.HashBytes(b); got != hash {
		return nil, fmt.Errorf("blob corrupt: stored %s but content is %s", hash, got)
	}
	return b, nil
}

// PutVerified stores b only if its content hash equals expected (trust the hash, not the
// source). This is the verify-on-receipt used by pinning.
func (s *Store) PutVerified(expected string, b []byte) error {
	if got := core.HashBytes(b); got != expected {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expected, got)
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
