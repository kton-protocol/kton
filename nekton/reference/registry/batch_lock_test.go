package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

func unscopedEnvelopes(t *testing.T, n int) []core.Envelope {
	t.Helper()
	envs := make([]core.Envelope, 0, n)
	for i := 0; i < n; i++ {
		env, _, err := claim.SignWith(note(fmt.Sprint("u", i)), keyOf("a"))
		if err != nil {
			t.Fatal(err)
		}
		envs = append(envs, env)
	}
	return envs
}

// R1 (kton-review on #281): a batch releases the write lock between chunks, so another process that
// needs it - a full Open numbering lines, another writer - gets it while the batch is still running.
func TestAddAllLetsOthersTakeTheLockMidBatch(t *testing.T) {
	defer func(d time.Duration) { batchChunk = d }(batchChunk)
	batchChunk = 20 * time.Millisecond
	dir := t.TempDir()
	r, err := OpenForWrite(dir)
	if err != nil {
		t.Fatal(err)
	}
	envs := unscopedEnvelopes(t, 3000)
	lp := filepath.Join(dir, ".objects.lock")
	done := make(chan error, 1)
	go func() { _, err := r.AddAll(envs); done <- err }()
	for { // wait until the batch holds the lock
		if _, err := os.Stat(lp); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the batch ended before it was seen holding the lock (err %v): make it longer", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	var during bool
	if err := withLockFile(lp, func() error {
		select {
		case <-done:
			during = false
		default:
			during = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !during {
		t.Fatal("the lock was granted only after the batch ended: a batch blocks every other open")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	full, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if full.Len() != len(envs) || full.Dropped() != 0 {
		t.Errorf("reopened: Len %d Dropped %d, want %d and 0", full.Len(), full.Dropped(), len(envs))
	}
}

// T19: a scope file loaded during a batch may hold lines whose positions the batch issued and has not
// written yet; loadScope takes them from the batch instead of asking for a full Open.
func TestLoadScopeSeesTheBatchsPositions(t *testing.T) {
	dir := t.TempDir()
	r, err := OpenForWrite(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := unscopedEnvelopes(t, 1)[0]
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	id := claim.ClaimID(payload)
	scope := scopeOf(st, id)
	path, err := subnektonPath(r.objectsDir, scope)
	if err != nil {
		t.Fatal(err)
	}
	r.batch = &batchState{seq: core.ReadSeqMap(filepath.Join(dir, seqFileName)), lines: map[string][]objectFile{}}
	defer func() { r.batch = nil }()
	if err := r.appendLine(path, objectFile{ClaimID: id, Envelope: env}); err != nil {
		t.Fatal(err)
	}
	r.batch.assign(r, []string{core.EnvelopeKey(env)})
	if err := r.loadScope(scope); errors.Is(err, ErrNeedsFullOpen) || err != nil {
		t.Fatalf("loadScope during a batch: %v", err)
	}
	if !r.seen[id] {
		t.Error("the batch's line was not loaded")
	}
}

// T20: a batch keeps its lock fresh, so a long chunk is not stolen as a crashed holder's (30 s).
func TestBatchRefreshesItsLock(t *testing.T) {
	lp := filepath.Join(t.TempDir(), ".objects.lock")
	if err := os.WriteFile(lp, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-20 * time.Second)
	if err := os.Chtimes(lp, old, old); err != nil {
		t.Fatal(err)
	}
	b := &batchState{lockPath: lp, touched: old}
	if err := b.locked(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(lp)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(fi.ModTime()) > 5*time.Second {
		t.Errorf("lock mtime is %v old after locked(): a long batch would be stolen", time.Since(fi.ModTime()))
	}
}

// R1, as kton-review reproduced it: a full Open in another registry during a batch that runs longer
// than a waiter's patience succeeds. Open numbers the batch's unpositioned lines under the write lock,
// so it needs the lock mid-batch. Here the waiter gives up after 40 x 5 ms = 200 ms and the batch runs
// well past that.
func TestOpenDuringALongBatchSucceeds(t *testing.T) {
	defer func(d time.Duration, n int) { batchChunk, lockAttempts = d, n }(batchChunk, lockAttempts)
	batchChunk, lockAttempts = 50*time.Millisecond, 40
	dir := t.TempDir()
	r, err := OpenForWrite(dir)
	if err != nil {
		t.Fatal(err)
	}
	envs := unscopedEnvelopes(t, 4000)
	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := r.AddAll(envs); done <- err }()
	time.Sleep(20 * time.Millisecond)
	opens := 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) < 400*time.Millisecond {
				t.Fatalf("the batch took %v, not longer than a waiter's 200 ms: make it longer", time.Since(start))
			}
			if opens == 0 {
				t.Fatal("no Open ran during the batch")
			}
			return
		default:
		}
		if _, err := Open(dir); err != nil {
			t.Fatalf("Open %d during the batch (%v in): %v", opens+1, time.Since(start), err)
		}
		opens++
	}
}
