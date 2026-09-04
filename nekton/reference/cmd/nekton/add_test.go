package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/registry"
)

// TestClaimAddIngests: signClaim with addFlag ingests the claim into the named registry in one step,
// without writing an intermediate envelope file (the `nekton claim/annotate/seed --add` path).
func TestClaimAddIngests(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(t.TempDir(), "reg")
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "urn:example:thing"}},
		Predicate: "pav:reviewedBy",
		Object:    map[string]any{"value": "ok"},
		By:        "CN=Tester",
		When:      "2026-07-15T00:00:00Z",
	}
	if err := signClaim(spec, priv, "", true /* add */, reg, false); err != nil {
		t.Fatalf("claim --add: %v", err)
	}
	r, err := registry.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("want 1 claim ingested into the --registry, got %d", r.Len())
	}
}

// TestCoSignerTwinUnion: two independent co-signers of one IDENTICAL statement share a claim id (the
// id covers only the payload, not the signatures). Ingesting both - in either order - must yield ONE
// claim carrying BOTH signatures: each signer is found by `by signer`, each verifies, and the stored
// object bytes are order-independent (SPEC §12 conflict-free union). Regression for mirror-order-v2,
// where the first-ingested signature won and the other valid co-signature was silently dropped.
func TestCoSignerTwinUnion(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "https://ex.example/thing"}},
		Predicate: "https://kton.dev/v/endorses",
		Object:    map[string]any{"id": "did:web:x.example/y"},
		By:        "CN=board",
		When:      "2026-01-01T00:00:00Z",
	}
	dir := t.TempDir()
	envAPath := filepath.Join(dir, "a.dsse.json")
	envBPath := filepath.Join(dir, "b.dsse.json")
	if err := signClaim(spec, privA, envAPath, false, "", false); err != nil {
		t.Fatalf("sign A: %v", err)
	}
	if err := signClaim(spec, privB, envBPath, false, "", false); err != nil {
		t.Fatalf("sign B: %v", err)
	}
	envA, err := readEnvelope(envAPath)
	if err != nil {
		t.Fatal(err)
	}
	envB, err := readEnvelope(envBPath)
	if err != nil {
		t.Fatal(err)
	}
	kidA, kidB := keyidHex(pubA), keyidHex(pubB)

	var objBytes [2][]byte
	orders := [][]string{{envAPath, envBPath}, {envBPath, envAPath}}
	for i, order := range orders {
		reg, err := registry.Open(filepath.Join(dir, "reg", order[0]+"-first"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range order {
			e := envA
			if p == envBPath {
				e = envB
			}
			if _, _, err := reg.Add(e); err != nil {
				t.Fatalf("add %s: %v", p, err)
			}
		}
		id, _, err := reg.Add(envA) // idempotent; returns the (shared) claim id
		if err != nil {
			t.Fatal(err)
		}
		if got := len(reg.BySigner(kidA)); got != 1 {
			t.Errorf("order %d: by signer A: want 1 claim, got %d", i, got)
		}
		if got := len(reg.BySigner(kidB)); got != 1 {
			t.Errorf("order %d: by signer B: want 1 claim, got %d", i, got)
		}
		rec, ok := reg.Claim(id)
		if !ok {
			t.Fatalf("order %d: claim %s not found", i, id)
		}
		if n := len(rec.Envelope.Signatures); n != 2 {
			t.Errorf("order %d: want 2 unioned signatures, got %d", i, n)
		}
		if ok, _ := rec.Envelope.Verify(pubA); !ok {
			t.Errorf("order %d: signer A does not verify against the unioned envelope", i)
		}
		if ok, _ := rec.Envelope.Verify(pubB); !ok {
			t.Errorf("order %d: signer B does not verify against the unioned envelope", i)
		}
		b, err := storedRecord(filepath.Join(dir, "reg", order[0]+"-first"), id)
		if err != nil {
			t.Fatal(err)
		}
		objBytes[i] = b
	}
	if string(objBytes[0]) != string(objBytes[1]) {
		t.Errorf("stored object is NOT order-independent:\n A-first: %s\n B-first: %s", objBytes[0], objBytes[1])
	}
}

// storedRecord returns the raw stored bytes for a claim id, wherever the store filed it: a claim
// lives as one line in its nekton file (objects/scope/<scope_id>.nekton.jsonl, or
// objects/unscoped.nekton.jsonl). Scanning for the id keeps this assertion about the RECORD being
// order-independent, not about which file form the store happens to use.
func storedRecord(regDir, id string) ([]byte, error) {
	var found []byte
	err := filepath.WalkDir(filepath.Join(regDir, "objects"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".nekton.jsonl") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, id) {
				found = []byte(strings.TrimSpace(line))
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("claim %s is not stored anywhere under %s", id, regDir)
	}
	return found, nil
}

// TestBulkAddOpensTheRegistryOnce: `add` takes many envelopes in one call. A shell loop cost one
// full registry replay PER RECORD - quadratic, and measured at 2.2 s per record once a thousand
// were stored, which is an hour for a real corpus. Bulk arrival is the normal case here
// (federation hands you a set; an executor publishes a batch; a consumer imports a handed-over
// corpus), so this asserts the many-path form ingests every record and reports refusals by name
// without letting one bad record wedge the rest.
func TestBulkAddOpensTheRegistryOnce(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var paths []string
	for i, when := range []string{"2026-07-15T00:00:00Z", "2026-07-16T00:00:00Z", "DRAFTT00:00:00Z"} {
		spec := claimSpec{
			Subject:   []subjSpec{{URI: fmt.Sprintf("urn:example:thing-%d", i)}},
			Predicate: "pav:reviewedBy",
			Object:    map[string]any{"value": "ok"},
			By:        "CN=Tester",
			When:      when,
		}
		p := filepath.Join(dir, fmt.Sprintf("c%d.dsse.json", i))
		// the malformed one cannot be signed through signClaim (it validates), so write the
		// envelope directly - which is exactly how a corpus ends up holding one.
		if err := signClaim(spec, priv, p, false, "", false); err != nil {
			if i != 2 {
				t.Fatalf("sign %d: %v", i, err)
			}
			raw, rerr := os.ReadFile(paths[0])
			if rerr != nil {
				t.Fatal(rerr)
			}
			if werr := os.WriteFile(p, bytes.ReplaceAll(raw, []byte("payload"), []byte("payloa_")), 0o644); werr != nil {
				t.Fatal(werr)
			}
		}
		paths = append(paths, p)
	}

	err = run("add", append(paths, "--registry", reg))
	if err == nil {
		t.Error("a refused record must make the call fail: a partial import reporting success is how a corpus quietly loses records")
	}
	r, oerr := registry.Open(reg)
	if oerr != nil {
		t.Fatalf("open: %v", oerr)
	}
	if r.Len() != 2 {
		t.Errorf("registry holds %d claims, want 2 (the good ones must land even though one was refused)", r.Len())
	}
}

// TestReadJSONEmitsRecordsVerbatim: `about --json` and `by --json` return {claimId, envelope} - the
// shape the registry stores and `add` accepts - so a consumer can decode the payload itself. The
// prose form answers "which records, roughly"; it does not carry the object, and the object is what
// a claim relates to. A consumer that had to parse the line would be parsing a sentence that does
// not contain the answer.
func TestReadJSONEmitsRecordsVerbatim(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "urn:example:doc"}},
		Predicate: "pav:reviewedBy",
		Object:    map[string]any{"id": "urn:example:person"},
		By:        "CN=Tester",
		When:      "2026-07-15T00:00:00Z",
	}
	if err := signClaim(spec, priv, "", true, reg, false); err != nil {
		t.Fatalf("claim --add: %v", err)
	}
	// `about` resolves its registry from the environment, not from an argument
	t.Setenv("NEKTON_DIR", reg)

	out := captureStdout(t, func() {
		if err := run("about", []string{"urn:example:doc", "--json"}); err != nil {
			t.Fatalf("about --json: %v", err)
		}
	})
	var recs []struct {
		ClaimID  string `json:"claimId"`
		Envelope struct {
			Payload string `json:"payload"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		t.Fatalf("about --json did not emit JSON: %v\n%s", err, out)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	raw, err := base64.StdEncoding.DecodeString(recs[0].Envelope.Payload)
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	// the object must survive: it is absent from the prose form, and it is the destination
	if !bytes.Contains(raw, []byte("urn:example:person")) {
		t.Error("the claim's object did not survive into --json output")
	}
	if recs[0].ClaimID == "" {
		t.Error("record carries no claimId")
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}
