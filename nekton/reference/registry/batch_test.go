package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// storeFiles reads every file under a store's objects dir, keyed by its relative path.
func storeFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	root := filepath.Join(dir, "objects")
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(root, p)
			out[rel] = b
		}
		return nil
	})
	return out
}

func seqOf(t *testing.T, dir string) map[string]int {
	return core.ReadSeqMap(filepath.Join(dir, seqFileName)).Seq
}

// batchEnvelopes: a chain written by Write, plus a co-signature of one claim, a re-add, an unsigned
// envelope, and one claim moved to the front so it arrives before its prev (deferred, then settled).
func batchEnvelopes(t *testing.T) []core.Envelope {
	t.Helper()
	src, _ := Open(t.TempDir())
	var envs []core.Envelope
	for i := 0; i < 30; i++ {
		w, err := src.Write(note(fmt.Sprint("c", i)), keyOf("a"))
		if err != nil {
			t.Fatal(err)
		}
		_ = w
	}
	for _, rec := range src.RawRecords() {
		envs = append(envs, rec.Envelope)
	}
	// co-signature: the same payload signed by another key
	payload, err := base64.StdEncoding.DecodeString(envs[5].Payload)
	if err != nil {
		t.Fatal(err)
	}
	k := keyOf("co")
	co, _, err := claim.Seal(payload, ed25519.Sign(k, core.PAE(envs[5].PayloadType, payload)), k.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	unsigned := envs[3]
	unsigned.Signatures = nil
	late := envs[len(envs)-1]
	out := append([]core.Envelope{late}, envs[:len(envs)-1]...)
	return append(out, co, envs[7], unsigned)
}

// AddAll leaves the store N Adds leave: the same files byte for byte, the same positions, the same
// per-envelope answers (kton-cockpit 20.11.).
func TestAddAllEqualsAddOneByOne(t *testing.T) {
	envs := batchEnvelopes(t)

	one, two := t.TempDir(), t.TempDir()
	r1, err := OpenForWrite(one)
	if err != nil {
		t.Fatal(err)
	}
	var want []AddResult
	for _, env := range envs {
		id, isNew, err := r1.Add(env)
		want = append(want, AddResult{ID: id, IsNew: isNew, Err: err})
	}
	r2, err := OpenForWrite(two)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r2.AddAll(envs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("AddAll gave %d results, Add %d", len(got), len(want))
	}
	refused := 0
	for i := range want {
		if got[i].ID != want[i].ID || got[i].IsNew != want[i].IsNew || (got[i].Err == nil) != (want[i].Err == nil) {
			t.Errorf("envelope %d: AddAll %+v, Add %+v", i, got[i], want[i])
		}
		if got[i].Err != nil {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("%d envelopes refused, want the unsigned one", refused)
	}
	f1, f2 := storeFiles(t, one), storeFiles(t, two)
	var names []string
	for n := range f1 {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(f1) != len(f2) {
		t.Errorf("files: Add %d, AddAll %d", len(f1), len(f2))
	}
	for _, n := range names {
		if !bytes.Equal(f1[n], f2[n]) {
			t.Errorf("%s differs between Add and AddAll", n)
		}
	}
	s1, s2 := seqOf(t, one), seqOf(t, two)
	if len(s1) != len(s2) || len(s1) == 0 {
		t.Fatalf("positions: Add %d, AddAll %d", len(s1), len(s2))
	}
	for k, v := range s1 {
		if s2[k] != v {
			t.Errorf("position of %s: Add %d, AddAll %d", k[:16], v, s2[k])
		}
	}
	// the lock is released and the store reopens whole with nothing dropped
	if _, err := os.Stat(filepath.Join(two, ".objects.lock")); !os.IsNotExist(err) {
		t.Errorf("write lock left behind: %v", err)
	}
	full, err := Open(two)
	if err != nil {
		t.Fatal(err)
	}
	if full.Dropped() != 0 || full.Len() != 31 {
		t.Errorf("reopened: Len %d Dropped %d, want 31 (30 and the root seed) and 0", full.Len(), full.Dropped())
	}
}
