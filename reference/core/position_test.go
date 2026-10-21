package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The position of a store changes when a record arrives - also when it arrives unnumbered, as by a
// git merge - and does not change when only bookkeeping does, or when nothing happens.
func TestReadPositionSeesUnnumberedArrivals(t *testing.T) {
	dir := t.TempDir()
	empty, err := ReadPosition(dir)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Epoch != "" || empty.MaxSeq != 0 {
		t.Errorf("a store with no numbering: %+v", empty)
	}
	again, _ := ReadPosition(dir)
	if again != empty {
		t.Error("an untouched store changed position between two reads")
	}

	obj := filepath.Join(dir, "objects", "sha256", "aa.json")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeqMap(filepath.Join(dir, ".seq"), SeqMap{Epoch: "e1", Next: 2, Seq: map[string]int{"sha256:aa": 1}}); err != nil {
		t.Fatal(err)
	}
	one, _ := ReadPosition(dir)
	if one.Epoch != "e1" || one.MaxSeq != 1 || one.Objects == empty.Objects {
		t.Errorf("after one numbered record: %+v", one)
	}

	// Bookkeeping alone - peers.json, a lock, the format marker - is not a change.
	for _, f := range []string{"peers.json", ".seq.lock", filepath.Join("objects", ".format")} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := ReadPosition(dir); p != one {
		t.Errorf("bookkeeping changed the position: %+v vs %+v", p, one)
	}

	// A record merged in by git: on disk, not numbered. MaxSeq cannot see it; Objects must.
	merged := filepath.Join(dir, "objects", "sha256", "bb.json")
	if err := os.WriteFile(merged, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	two, _ := ReadPosition(dir)
	if two.MaxSeq != one.MaxSeq || two.Objects == one.Objects {
		t.Errorf("an unnumbered arrival was not seen: %+v vs %+v", two, one)
	}

	// An append (material, a nekton scope file) is a change too.
	later := time.Now().Add(time.Second)
	f, _ := os.OpenFile(merged, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("\n"))
	f.Close()
	os.Chtimes(merged, later, later)
	if p, _ := ReadPosition(dir); p.Objects == two.Objects {
		t.Error("an appended file was not seen")
	}
}
