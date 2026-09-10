package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

// AUD-05. `nekton mirror` classified EVERY Add error as a retryable missing dependency and, after
// retrying it pointlessly, reported a local write failure as
//
//	"1 unresolved (missing dependency - an incomplete chain)"   exit 0
//
// That is not imprecision: a missing dependency never reaches that branch at all, because Add
// PERSISTS an unresolved claim and returns nil (§11: incomplete is not invalid). So the only errors
// that could arrive were permanent or environmental, and the environmental ones were reported as
// the one thing they were not.
//
// ErrPersist is what lets a caller tell "this claim is invalid, skip it" from "I could not write,
// nothing was stored". A mirror that reports success while storing nothing is the worst possible
// outcome for a tool whose whole job is evidence.
func TestAddReportsALocalWriteFailureAsSuch(t *testing.T) {
	dir := t.TempDir()

	// Put a regular file where the store needs to write its unscoped nekton.
	objects := filepath.Join(dir, "objects")
	if err := os.MkdirAll(objects, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(objects, "unscoped.nekton.jsonl"), []byte("blockade"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(objects, "unscoped.nekton.jsonl"), 0o444); err != nil {
		t.Fatal(err)
	}

	r, err := registry.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _, err = r.Add(signedClaim(t))
	if err == nil {
		t.Fatal("Add succeeded even though the store could not be written")
	}
	if !errors.Is(err, registry.ErrPersist) {
		t.Fatalf("a local write failure must be distinguishable from an invalid record;\n got: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "dependency") {
		t.Errorf("a write failure must not be described as a missing dependency: %v", err)
	}
}

// The other half of the same rule: a record the kernel REFUSES must not look like a write failure,
// or a caller cannot tell whose problem it is.
func TestAnInvalidRecordIsNotAPersistenceFailure(t *testing.T) {
	r, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := signedClaim(t)
	env.Signatures = nil // a claim is constituted by its signature (§7.2)
	_, _, err = r.Add(env)
	if err == nil {
		t.Fatal("an unsigned claim was ingested")
	}
	if errors.Is(err, registry.ErrPersist) {
		t.Errorf("an invalid record was reported as a local write failure: %v", err)
	}
}

func signedClaim(t *testing.T) core.Envelope {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"sha256": strings.Repeat("ab", 32)}}},
		"predicateType": claim.PredicateType,
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/v/note"},
			"by":        "CN=a",
			"when":      "2026-07-16T00:00:00Z",
		},
	}
	raw, err := core.CanonValue(st)
	if err != nil {
		t.Fatal(err)
	}
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(raw)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(core.PayloadType, raw)))})
	return env
}
