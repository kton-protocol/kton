package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/registry"
)

// A bufio.Scanner stops at the FIRST error and reports it only through Err(), which neither material
// reader checked. One line longer than the buffer therefore ended the loop silently and every
// attachment AFTER it vanished - the file read as if it simply ended.
//
// §8.1 says material must never affect a record's validity, and it does not. But evidence that
// disappears without a word is the failure this substrate exists to prevent, so the reader now says
// the file is incomplete. It still returns what it could read: one oversized line must not hide the
// attachments before it either.
func TestAnOversizedMaterialLineIsReportedNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	objects := filepath.Join(dir, "objects")
	if err := os.MkdirAll(objects, 0o755); err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("ab", 32)
	good := `{"subject":"` + subject + `","scheme":"first","material":"eA=="}`
	// Comfortably past the 16 MiB cap the readers set.
	huge := `{"subject":"` + subject + `","scheme":"huge","material":"` + strings.Repeat("A", 17<<20) + `"}`
	after := `{"subject":"` + subject + `","scheme":"after","material":"eA=="}`

	path := filepath.Join(objects, "material.jsonl")
	if err := os.WriteFile(path, []byte(good+"\n"+huge+"\n"+after+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		r, err := registry.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		got := r.Material(subject)
		// What came BEFORE the bad line must survive: one oversized line is not a reason to lose
		// everything, any more than it is a reason to lose nothing.
		if len(got) < 1 || got[0].Scheme != "first" {
			t.Errorf("the attachment before the oversized line was lost: %+v", got)
		}
	})
	if !strings.Contains(stderr, "INCOMPLETE") {
		t.Errorf("reading stopped early and said nothing; stderr was:\n%s", stderr)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wr
	fn()
	wr.Close()
	os.Stderr = old
	buf := make([]byte, 64<<10)
	n, _ := rd.Read(buf)
	rd.Close()
	return string(buf[:n])
}
