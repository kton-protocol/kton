package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/registry"
)

// TestMaterialSurvivesATornTail: #143 fixed a torn JSONL tail losing a successful append, and the
// record log isolates one before writing. The MATERIAL log did not, though the failure mode is
// identical: a crash mid-append leaves an unterminated line, a bare O_APPEND write lands on it,
// concatenating the two, and the reader discards BOTH - so an acknowledged attach is lost to
// somebody else's interrupted one.
//
// That it is material rather than a record does not make it smaller: §8.1 material is the evidence
// a proof is filed under, and losing it silently is how an anchored record ends up with nothing to
// show.
func TestMaterialSurvivesATornTail(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Material binds to a record the store holds, so put a real one there first.
	env, subject := signFoton(t, strings.Repeat("a", 64), nil)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}

	// A first, complete attach.
	if err := r.AttachMaterial(registry.VerificationMaterial{
		Subject: subject, Scheme: "rekor-entry", MediaType: "application/json", Material: "AAA=",
	}); err != nil {
		t.Fatal(err)
	}

	// Find the material log and TEAR it: append an unterminated line, as a crash mid-write leaves.
	var path string
	err = filepath.Walk(dir, func(p string, fi os.FileInfo, e error) error {
		if e == nil && !fi.IsDir() && strings.Contains(p, "material") {
			path = p
		}
		return nil
	})
	if err != nil || path == "" {
		t.Fatalf("cannot find the material log under %s (err=%v)", dir, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"subject":"` + subject + `","scheme":"tor`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// A second attach after the tear.
	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.AttachMaterial(registry.VerificationMaterial{
		Subject: subject, Scheme: "rfc3161", MediaType: "application/timestamp-reply", Material: "BBB=",
	}); err != nil {
		t.Fatal(err)
	}

	// Both the earlier complete entry and the acknowledged one must be there after a reopen.
	r3, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	schemes := map[string]bool{}
	for _, m := range r3.Material(subject) {
		schemes[m.Scheme] = true
	}
	if !schemes["rfc3161"] {
		t.Error("the attach that was acknowledged after the tear is gone - it was concatenated onto " +
			"the torn line and the reader discarded both")
	}
	if !schemes["rekor-entry"] {
		t.Error("the earlier complete entry was lost with the torn one")
	}
}
