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
	// The escape is built at run time so no editor or tool normalises it away: \u0073 is "s".
	bs := string(rune(92))
	escaped := `{"claimId":"` + bs + `u0073ha256:` + strings.Repeat("a", 64) + `"}`
	if strings.Contains(escaped, id) || !strings.Contains(escaped, bs) {
		t.Fatalf("the escaped line must spell the id only through an escape: %s", escaped)
	}
	p := filepath.Join(t.TempDir(), "s.jsonl")
	body := `{"claimId":"` + id + `"}` + "\n" + `{"claimId":"` + other + `"}` + "\n" + escaped + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := readSubnektonFor(p, id)
	if len(got) != 2 || got[0].ClaimID != id || got[1].ClaimID != id {
		t.Fatalf("readSubnektonFor = %+v, want the plain and the escaped line", got)
	}
	if all, _ := readSubnekton(p); len(all) != 3 {
		t.Errorf("readSubnekton = %d lines, want 3", len(all))
	}
}
