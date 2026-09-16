package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestEveryVerifyExitCodeIsDocumented: `verify`'s exit codes are a CONTRACT - a caller branches on
// them - and they are stated in two places a reader trusts: the built-in help and nekton.1. Adding a
// code to the dispatch without adding it to both is how documentation comes to advertise a surface
// the binary does not have, which is the drift #46 and #117 were filed for.
//
// So this reads the codes out of the source of truth - the os.Exit calls in the verify branch - and
// requires each one to appear in both documents. It fails when a code is added, not months later
// when somebody spot-checks the man page.
func TestEveryVerifyExitCodeIsDocumented(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	// The verify branch, from `case "verify":` to the next top-level case.
	text := string(src)
	i := strings.Index(text, `case "verify":`)
	if i < 0 {
		t.Fatal(`no "verify" case in main.go - this test is looking at the wrong thing`)
	}
	rest := text[i+len(`case "verify":`):]
	if j := strings.Index(rest, "\n\tcase \""); j >= 0 {
		rest = rest[:j]
	}
	codes := map[string]bool{"0": true} // success is the documented default
	for _, m := range regexp.MustCompile(`os\.Exit\((\d+)\)`).FindAllStringSubmatch(rest, -1) {
		codes[m[1]] = true
	}
	if len(codes) < 4 {
		t.Fatalf("found only %d exit codes in the verify branch (%v) - the extraction is broken, "+
			"and a test that finds nothing proves nothing", len(codes), codes)
	}

	help, err := os.ReadFile("main.go") // usage text lives in main.go
	if err != nil {
		t.Fatal(err)
	}
	man, err := os.ReadFile("nekton.1")
	if err != nil {
		t.Fatal(err)
	}
	// Both documents state the codes in prose; look for the digit in the verify passage of each.
	helpVerify := section(t, string(help), "nekton verify <envelope.dsse.json|sha256:id>", "nekton records")
	manVerify := section(t, string(man), ".B nekton verify", ".TP\n.B nekton about")

	for code := range codes {
		if code == "0" {
			continue // "exit 0" / "Exit status: 0" - covered by the passages themselves
		}
		if !strings.Contains(helpVerify, code) {
			t.Errorf("exit code %s is not mentioned in `nekton help` - a caller branching on it has "+
				"no way to learn it exists", code)
		}
		if !strings.Contains(manVerify, code) {
			t.Errorf("exit code %s is not mentioned in nekton.1 - the man page would describe a "+
				"smaller contract than the binary has", code)
		}
	}
}

func section(t *testing.T, doc, from, to string) string {
	t.Helper()
	i := strings.Index(doc, from)
	if i < 0 {
		t.Fatalf("cannot find %q - this test is reading the wrong document", from)
	}
	rest := doc[i:]
	if j := strings.Index(rest, to); j > 0 {
		rest = rest[:j]
	}
	return rest
}
