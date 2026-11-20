package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readSubnektonFor skips lines that cannot carry the id undecoded, and still finds a line that spells
// the id with a JSON escape (kton-cockpit 20.11.: persistClaim decoded the whole scope per Add).
func TestReadSubnektonForKeepsEveryLineThatCanCarryTheID(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	escaped := `{"claimId":"sha256:` + strings.Repeat("a", 64) + `"}`
	p := filepath.Join(t.TempDir(), "s.jsonl")
	body := `{"claimId":"` + id + `"}` + "\n" + `{"claimId":"` + other + `"}` + "\n" + escaped + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readSubnektonFor(p, id)
	if len(got) != 2 || got[0].ClaimID != id || got[1].ClaimID != id {
		t.Fatalf("readSubnektonFor = %+v, want the plain and the escaped line", got)
	}
	if all := readSubnekton(p); len(all) != 3 {
		t.Errorf("readSubnekton = %d lines, want 3", len(all))
	}
}
