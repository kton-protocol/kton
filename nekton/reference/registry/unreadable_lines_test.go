package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #287: UnreadableLines names the lines Unreadable counts: file, line, byte offset and first bytes,
// so a torn tail or a merge-conflict marker can be removed by hand.
func TestUnreadableLinesNamesEachLine(t *testing.T) {
	dir := t.TempDir()
	if got, err := UnreadableLines(dir); err != nil || len(got) != 0 {
		t.Fatalf("no store yet: %v, %v; want none", got, err)
	}
	r, _ := Open(dir)
	if _, err := r.Write(note("a"), keyOf("a")); err != nil {
		t.Fatal(err)
	}
	if got, err := UnreadableLines(dir); err != nil || len(got) != 0 {
		t.Fatalf("a whole store: %v, %v; want none", got, err)
	}
	var f string
	filepath.Walk(filepath.Join(dir, "objects"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && f == "" && strings.HasSuffix(p, ".nekton.jsonl") {
			f = p
		}
		return nil
	})
	if f == "" {
		t.Fatal("no scope file")
	}
	before, _ := os.ReadFile(f)
	wholeLines := strings.Count(string(before), "\n")
	long := `{"claimId":"` + strings.Repeat("x", 200)
	fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString("<<<<<<< HEAD\n\n" + long + "\n")
	fh.Close()

	got, err := UnreadableLines(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d lines, want the marker and the torn line: %+v", len(got), got)
	}
	reopened, _ := Open(dir)
	if reopened.Unreadable() != len(got) {
		t.Errorf("Unreadable() = %d, UnreadableLines = %d: they must agree", reopened.Unreadable(), len(got))
	}
	rel, _ := filepath.Rel(dir, f)
	b, _ := os.ReadFile(f)
	for i, want := range []struct {
		line int
		head string
	}{{wholeLines + 1, "<<<<<<< HEAD"}, {wholeLines + 3, long[:unreadableHeadBytes]}} {
		l := got[i]
		if l.File != filepath.ToSlash(rel) || l.Line != want.line || l.Head != want.head || l.Err == "" {
			t.Errorf("entry %d = %+v, want %s:%d starting %q with an error", i, l, rel, want.line, want.head)
		}
		if !strings.HasPrefix(string(b[l.Offset:]), want.head) {
			t.Errorf("entry %d: offset %d does not point at the line", i, l.Offset)
		}
	}
}

// kton-review V2 on #297: a store of a newer format is refused, as Open refuses it, not listed line
// by line as unreadable. Nothing is written to it.
func TestUnreadableLinesRefusesANewerFormat(t *testing.T) {
	dir := t.TempDir()
	r, _ := Open(dir)
	if _, err := r.Write(note("a"), keyOf("a")); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "objects", formatMarker)
	newer := []byte("nekton-store 99\n")
	if err := os.WriteFile(marker, newer, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := UnreadableLines(dir); err == nil || !strings.Contains(err.Error(), "format 99") {
		t.Fatalf("newer format: %v, %v; want a refusal naming the format", got, err)
	}
	if b, _ := os.ReadFile(marker); string(b) != string(newer) {
		t.Errorf("the marker changed: %q", b)
	}
}

// The offset points at the head's first byte, also for a line with leading blanks.
func TestUnreadableLinesOffsetMatchesHead(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "objects", "unscoped.nekton.jsonl")
	content := "\n   \t<<<<<<< HEAD\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := UnreadableLines(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	if l := got[0]; l.Line != 2 || !strings.HasPrefix(content[l.Offset:], l.Head) || l.Head != "<<<<<<< HEAD" {
		t.Errorf("%+v: offset does not point at the head", l)
	}
}
