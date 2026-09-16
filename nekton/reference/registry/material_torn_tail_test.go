package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/registry"
)

// The nekton half of the material torn-tail repair. Same failure mode as the record log's (#143):
// a crash mid-append leaves an unterminated line, a bare O_APPEND write concatenates onto it, and
// the reader discards BOTH - so an acknowledged attach is lost to somebody else's interrupted one.
func TestMaterialSurvivesATornTail(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, id := mkClaim(t, priv, "urn:target", "1")

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	if err := r.AttachMaterial(registry.VerificationMaterial{
		Subject: id, Scheme: "rekor-entry", MediaType: "application/json", Material: "AAA=",
	}); err != nil {
		t.Fatal(err)
	}

	// Tear the material log the way a crash mid-write leaves it.
	var path string
	if err := filepath.Walk(dir, func(p string, fi os.FileInfo, e error) error {
		if e == nil && !fi.IsDir() && strings.Contains(p, "material") {
			path = p
		}
		return nil
	}); err != nil || path == "" {
		t.Fatalf("cannot find the material log under %s (err=%v)", dir, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"subject":"` + id + `","scheme":"tor`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r2, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.AttachMaterial(registry.VerificationMaterial{
		Subject: id, Scheme: "rfc3161", MediaType: "application/timestamp-reply", Material: "BBB=",
	}); err != nil {
		t.Fatal(err)
	}

	r3, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	schemes := map[string]bool{}
	for _, m := range r3.Material(id) {
		schemes[m.Scheme] = true
	}
	if !schemes["rfc3161"] {
		t.Error("the attach acknowledged after the tear is gone - it was concatenated onto the torn " +
			"line and the reader discarded both")
	}
	if !schemes["rekor-entry"] {
		t.Error("the earlier complete entry was lost with the torn one")
	}
}
