package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

func lazyKey() ed25519.PrivateKey {
	s := sha256.Sum256([]byte("lazy"))
	return ed25519.NewKeyFromSeed(s[:])
}

// snapshot is every file under dir (relative path -> bytes).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".lock") {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		out[rel] = string(b)
		return nil
	})
	return out
}

// The same writes through a write registry and through a full Open leave byte-identical stores (#248).
func TestWriteToEqualsFullOpen(t *testing.T) {
	priv := lazyKey()
	when := "2026-11-18T00:00:00Z"
	defer func(f func() string) { now = f }(now)
	now = func() string { return when }
	note := func(i int) claim.Spec {
		return claim.Spec{Subject: []claim.SubjectSpec{{URI: fmt.Sprint("urn:n", i)}}, Predicate: "https://kton.dev/v/x", By: "b", When: when}
	}
	seed := claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:nekton:scope:s"}}, PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "s", "genesis": true, "by": "b", "when": when}}
	run := func(dir string, write func(claim.Spec) (Written, error)) {
		full, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := full.CreateRoot(priv, "b", when, "root/eq"); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, err := write(note(i)); err != nil {
				t.Fatal(err)
			}
		}
		w, err := write(seed)
		if err != nil {
			t.Fatal(err)
		}
		in := note(9)
		in.Scope, in.Prev = w.ID, w.ID
		if _, err := write(in); err != nil {
			t.Fatal(err)
		}
	}
	a, b := t.TempDir(), t.TempDir()
	run(a, func(s claim.Spec) (Written, error) { return WriteTo(a, s, priv) })
	run(b, func(s claim.Spec) (Written, error) {
		r, err := Open(b)
		if err != nil {
			return Written{}, err
		}
		return r.Write(s, priv)
	})
	sa, sb := snapshot(t, a), snapshot(t, b)
	var names []string
	for k := range sa {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(sa) != len(sb) {
		t.Fatalf("files differ: %v vs %d files", names, len(sb))
	}
	for _, k := range names {
		if k == ".seq" { // the epoch is random per store by design; positions and next must agree
			sa[k], sb[k] = dropEpoch(t, sa[k]), dropEpoch(t, sb[k])
		}
		if sa[k] != sb[k] {
			t.Errorf("%s differs:\n%s\n---\n%s", k, sa[k], sb[k])
		}
	}
	ra, _ := Open(a)
	rb, _ := Open(b)
	if ra.Len() != rb.Len() || ra.MaxSeq() != rb.MaxSeq() {
		t.Errorf("full reads differ: %d/%d claims, maxSeq %d/%d", ra.Len(), rb.Len(), ra.MaxSeq(), rb.MaxSeq())
	}
	if ha, _, _ := ra.Heads(ra.Root()); len(ha) != 1 {
		t.Errorf("root heads after lazy writes: %v", ha)
	}
}

// A record on disk without a position makes the write registry step aside; WriteTo then writes
// through a full Open, so the numbering stays what a full Open gives.
func TestUnnumberedRecordFallsBackToFullOpen(t *testing.T) {
	dir := t.TempDir()
	priv := lazyKey()
	env, _, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:merged"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	// planted as a merge would leave it: a line in the unscoped file, no .seq entry
	path := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line, _ := marshalRecord(objectFile{ClaimID: mustID(t, env), Envelope: env})
	if err := os.WriteFile(path, append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := OpenForWrite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Add(env); !errors.Is(err, ErrNeedsFullOpen) {
		t.Fatalf("write registry over an unnumbered record: %v, want ErrNeedsFullOpen", err)
	}
	if _, err := WriteTo(dir, claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:new"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z", Scope: "", Prev: ""}, priv); err != nil {
		t.Fatalf("WriteTo did not fall back: %v", err)
	}
}

func dropEpoch(t *testing.T, s string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "epoch")
	b, _ := json.Marshal(m)
	return string(b)
}

func mustID(t *testing.T, env interface{ PayloadBytes() ([]byte, error) }) string {
	t.Helper()
	b, err := env.PayloadBytes()
	if err != nil {
		t.Fatal(err)
	}
	return claim.ClaimID(b)
}

// W1: a root file holding a record no position was issued for (a merged copy) makes the write registry
// step aside BEFORE anything is stored, so a new seed is stored once and registered (#269 review).
func TestFallbackStillRegistersANewSeed(t *testing.T) {
	priv := lazyKey()
	a, b := t.TempDir(), t.TempDir()
	ra, _ := Open(a)
	if _, err := ra.CreateRoot(priv, "b", "2026-11-18T00:00:00Z", "root/w1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ra.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:a"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv); err != nil {
		t.Fatal(err)
	}
	// a copy writes one entry; its root file is merged into a's as a git merge would (no .seq entry)
	copyDir(t, a, b)
	rb, _ := Open(b)
	wb, err := rb.Write(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:b"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:01Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	rootFile, _ := subnektonPath(filepath.Join(a, "objects"), ra.Root())
	recB, _ := rb.Claim(wb.ID)
	line, _ := marshalRecord(objectFile{ClaimID: wb.ID, Envelope: recB.Envelope})
	f, _ := os.OpenFile(rootFile, os.O_APPEND|os.O_WRONLY, 0o644)
	f.Write(append(line, '\n'))
	f.Close()

	seed := claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:nekton:scope:child"}}, PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": "child", "genesis": true, "by": "b", "when": "2026-11-18T10:00:05Z"}}
	w, err := WriteTo(a, seed, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !w.IsNew || w.Registered == "" {
		t.Fatalf("seed write through the fallback: %+v, want new and registered", w)
	}
	full, _ := Open(a)
	if !full.Registered()[w.ID] {
		t.Errorf("the root does not list the new seed")
	}
}

// D1: the write path refuses a 0.2 per-claim store as Open does, and writes nothing into it.
func TestWriteToRefusesLegacyStore(t *testing.T) {
	dir := t.TempDir()
	priv := lazyKey()
	env, id, err := claim.SignWith(claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:old"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	flat := filepath.Join(dir, "objects", "sha256")
	os.MkdirAll(flat, 0o755)
	b, _ := json.Marshal(objectFile{ClaimID: id, Envelope: env})
	if err := os.WriteFile(filepath.Join(flat, strings.TrimPrefix(id, "sha256:")+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = WriteTo(dir, claim.Spec{Subject: []claim.SubjectSpec{{URI: "urn:new"}}, Predicate: "https://kton.dev/v/x", By: "b", When: "2026-11-18T00:00:00Z"}, priv)
	if err == nil || !strings.Contains(err.Error(), "per-claim layout") {
		t.Fatalf("WriteTo into a 0.2 store: %v, want the layout refusal", err)
	}
	for _, f := range []string{".format", ".root"} {
		if _, err := os.Stat(filepath.Join(dir, "objects", f)); err == nil {
			t.Errorf("objects/%s was written into a refused store", f)
		}
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(target, b, 0o644)
	})
}
