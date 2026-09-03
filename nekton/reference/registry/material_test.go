package registry

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

func attachable(t *testing.T) (*Registry, string, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	priv := testKey(t, 7)
	env, scopeID := sign(t, seedSpec("lab/material"), priv)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	loose, looseID := sign(t, claim.Spec{
		Subject:   []claim.SubjectSpec{{URI: "urn:demo:loose"}},
		Predicate: "https://example.org/v/noted",
		By:        "key:test", When: "2026-08-24T00:00:00Z",
	}, priv)
	if _, _, err := r.Add(loose); err != nil {
		t.Fatal(err)
	}
	return r, scopeID, looseID
}

// Material lands BESIDE the subnekton it is about, so handing a scope over hands its evidence over
// too - and so that a build which does not know about it ignores a file rather than rewriting
// records without it (SPEC §8.1, #62).
func TestMaterialLandsBesideItsSubnekton(t *testing.T) {
	r, scopeID, looseID := attachable(t)
	dir := r.dir

	for id, want := range map[string]string{
		scopeID: filepath.Join("objects", "scope", bare(scopeID)+".material.jsonl"),
		looseID: filepath.Join("objects", "unscoped.material.jsonl"),
	} {
		if err := r.AttachMaterial(VerificationMaterial{
			Subject: id, Scheme: "sigstore-bundle",
			MediaType: "application/vnd.dev.sigstore.bundle.v1+json",
			Material:  base64.StdEncoding.EncodeToString([]byte(`{"pretend":"bundle"}`)),
		}); err != nil {
			t.Fatalf("attach %s: %v", id, err)
		}
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("material for %s not at %s: %v", id[:16], want, err)
		}
	}

	// The subnekton itself must be untouched - the record file carries records, nothing else.
	body, err := os.ReadFile(filepath.Join(dir, "objects", "scope", bare(scopeID)+".nekton.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "sigstore-bundle") {
		t.Error("material leaked into the subnekton file")
	}

	// It survives a reopen, and is not mistaken for a record.
	r2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r2.Material(scopeID)); got != 1 {
		t.Errorf("material after reopen = %d, want 1", got)
	}
	if got := len(r2.records); got != 2 {
		t.Errorf("registry holds %d records, want 2 - material files must not be read as records", got)
	}
}

// §8.1: presence, absence or invalidity MUST NOT affect a record's validity or resolvability. This
// is the boundary that makes attaching evidence safe at all - so it is tested with a file that is
// not merely unknown but broken.
func TestBrokenMaterialCannotBreakARecordRead(t *testing.T) {
	r, scopeID, _ := attachable(t)
	dir := r.dir

	bad := filepath.Join(dir, "objects", "scope", bare(scopeID)+".material.jsonl")
	if err := os.WriteFile(bad, []byte("not json at all\n{\"subject\":\"\"}\n{{{\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(dir)
	if err != nil {
		t.Fatalf("a corrupt material file broke the registry read: %v", err)
	}
	if len(r2.records) != 2 {
		t.Errorf("records = %d, want 2 - a corrupt material file must not cost a record", len(r2.records))
	}
	if _, ok := r2.Claim(scopeID); !ok {
		t.Error("the seed stopped resolving because its material file was corrupt")
	}
	if got := len(r2.Material(scopeID)); got != 0 {
		t.Errorf("unreadable material was indexed anyway: %d", got)
	}
}

// An unknown scheme MUST be carried, not rejected: refusing unknown evidence would make the scheme
// list a protocol version, which is what §8.1 exists to avoid.
func TestUnknownSchemeIsCarried(t *testing.T) {
	r, scopeID, _ := attachable(t)
	if err := r.AttachMaterial(VerificationMaterial{
		Subject: scopeID, Scheme: "something-invented-in-2031",
		MediaType: "application/octet-stream",
		Material:  base64.StdEncoding.EncodeToString([]byte("opaque")),
	}); err != nil {
		t.Fatalf("an unknown scheme was rejected: %v", err)
	}
	r2, err := Open(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	got := r2.Material(scopeID)
	if len(got) != 1 || got[0].Scheme != "something-invented-in-2031" {
		t.Errorf("unknown scheme did not survive: %+v", got)
	}
}

// Material binds to a record's CONTENT ADDRESS. Attaching it to something this registry does not
// hold would produce evidence about nothing, bound by a name rather than by a hash.
func TestMaterialNeedsARecordToBindTo(t *testing.T) {
	r, _, _ := attachable(t)
	err := r.AttachMaterial(VerificationMaterial{
		Subject: "sha256:" + strings.Repeat("f", 64), Scheme: "rfc3161",
		Material: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil {
		t.Error("material was attached to a subject the registry does not hold")
	}
}

// `scope` is a free-form string in a SIGNED CLAIM PAYLOAD - attacker-chosen, and ingest does not
// verify signatures (SPEC §8), so any key will do. The store derived a filename from it unvalidated,
// which let a claim write outside the store and, on a second ingest, truncate the file it landed in.
//
// Same class as the blobstore path (#79): validate before deriving a path. Fixed in one kernel and
// left in the other, which is why this asserts the property rather than the symptom.
func TestAScopeCannotNameAFileOutsideTheStore(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{
		"sha256:../../../../etc/passwd",
		"../../../etc/passwd",
		"sha256:" + strings.Repeat("z", 64), // right length, not hex
		"sha256:/absolute/path",
		"sha256:a/b",
		"not-a-hash",
	} {
		if p, err := subnektonPath(filepath.Join(dir, "objects"), scope); err == nil {
			t.Errorf("subnektonPath(%q) = %q; want a refusal", scope, p)
		}
		if p, err := materialPath(filepath.Join(dir, "objects"), scope); err == nil {
			t.Errorf("materialPath(%q) = %q; want a refusal - both derive from the same field", scope, p)
		}
	}

	// A real scope still resolves, in every spelling SPEC §5.1 accepts.
	real := "sha256:" + strings.Repeat("a", 64)
	for _, form := range []string{real, strings.ToUpper(real), strings.Repeat("a", 64)} {
		p, err := subnektonPath(filepath.Join(dir, "objects"), form)
		if err != nil {
			t.Errorf("subnektonPath(%q): %v", form, err)
			continue
		}
		if !strings.HasSuffix(p, strings.Repeat("a", 64)+".nekton.jsonl") {
			t.Errorf("subnektonPath(%q) = %q; spellings must fold to one file", form, p)
		}
	}
	_ = r
}
