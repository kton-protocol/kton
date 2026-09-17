package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// TestStoredIdentityIsDerivedNotDeclared: a stored row's `claimId` is a CACHE of
// sha256(canon(Statement)), never the identity itself. Two distinct signed claims whose rows carry
// an empty - or entirely absent - claimId used to collapse into one:
//
//	Len()=1  len(Records(0))=2  Dropped()=0
//	Claim(idA) found=false   Claim(idB) found=false   both feed rows: claimId=""
//
// The admission gate only compared the stored id to the derived one when the stored one was
// NONEMPTY, so "" passed, and every downstream map (seen, claimByID, feed) was keyed on "". Two
// claims share one key; neither is retrievable by its real id; and the feed publishes empty ids to
// peers while reporting no rejection. Reaching it needs no forged signature - only a malformed row
// arriving through filesystem/git federation.
//
// Both read paths, both spellings. A test that covered only Open would have missed the union, which
// re-runs settle over foreign rows.
func TestStoredIdentityIsDerivedNotDeclared(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envA, idA := mkClaim(t, priv, "urn:t:A", "a")
	envB, idB := mkClaim(t, priv, "urn:t:B", "b")
	if idA == idB {
		t.Fatal("test is vacuous: the two claims share an id")
	}

	// omit=true writes no claimId property at all; omit=false writes it as "".
	store := func(t *testing.T, omit bool) string {
		t.Helper()
		dir := t.TempDir()
		objs := filepath.Join(dir, "objects")
		if err := os.MkdirAll(objs, 0o755); err != nil {
			t.Fatal(err)
		}
		var buf []byte
		for _, env := range []core.Envelope{envA, envB} {
			row := map[string]any{"envelope": env}
			if !omit {
				row["claimId"] = ""
			}
			line, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			buf = append(append(buf, line...), '\n')
		}
		if err := os.WriteFile(filepath.Join(objs, "unscoped.nekton.jsonl"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	check := func(t *testing.T, r *registry.Registry) {
		t.Helper()
		// Whatever the policy - refuse the rows or recover their ids - the two claims must never
		// share one identity, and no row may reach a peer under an id it does not derive.
		for _, id := range []string{idA, idB} {
			rec, ok := r.Claim(id)
			if !ok {
				t.Errorf("Claim(%s): not held; the store dropped a validly signed claim", id[:16])
				continue
			}
			if rec.ClaimID != id {
				t.Errorf("Claim(%s): held under ClaimID %q", id[:16], rec.ClaimID)
			}
		}
		if n := r.Len(); n != 2 {
			t.Errorf("Len()=%d, want 2: two distinct claims, two entries", n)
		}
		for i, rec := range r.Records(0) {
			if rec.ClaimID == "" {
				t.Errorf("feed row %d publishes an empty claim id", i)
			}
			if rec.ClaimID != idA && rec.ClaimID != idB {
				t.Errorf("feed row %d publishes id %q, which is neither claim", i, rec.ClaimID)
			}
		}
	}

	for _, tc := range []struct {
		name string
		omit bool
	}{{"empty", false}, {"omitted", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := store(t, tc.omit)
			t.Run("Open", func(t *testing.T) {
				r, err := registry.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				check(t, r)
			})
			t.Run("OpenUnion", func(t *testing.T) {
				r, err := registry.OpenUnion(dir, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				check(t, r)
			})
		})
	}
}
