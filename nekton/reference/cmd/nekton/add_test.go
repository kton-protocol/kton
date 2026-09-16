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
	"sort"
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
		Predicate: "https://kton.dev/v/reviewed",
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
		// A LABEL, not a path. This used to be order[0]+"-first", where order[0] is an absolute
		// path - which on Windows contains a drive letter and produced `...\\reg\\C::`, an invalid
		// name. A test-setup bug, but it kept the whole package red on a platform we ship.
		reg, err := registry.Open(filepath.Join(dir, "reg", fmt.Sprintf("order-%d", i)))
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
		// Order-independence is asserted on the RESOLVED state, not on the file.
		//
		// A subnekton is an APPEND-ONLY log, because in nekton the order carries meaning (prev,
		// head, seal). A co-signature is therefore a new LINE, not a rewrite of the existing one -
		// which is what gives it a position of its own and lets a cursor deliver it. Two
		// peers that received A-then-B and B-then-A hold the same lines in a different order, so the
		// FILES differ by construction and comparing their first line asserts the wrong thing.
		//
		// What must be order-independent is what the store MEANS: the same claim, carrying the same
		// set of signatures, whichever order they arrived in.
		sigs := make([]string, 0, len(rec.Envelope.Signatures))
		for _, sg := range rec.Envelope.Signatures {
			sigs = append(sigs, sg.KeyID+" "+sg.Sig)
		}
		sort.Strings(sigs)
		objBytes[i] = []byte(id + "\n" + strings.Join(sigs, "\n"))
	}
	if string(objBytes[0]) != string(objBytes[1]) {
		t.Errorf("the resolved claim is NOT order-independent:\n A-first: %s\n B-first: %s", objBytes[0], objBytes[1])
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
			Predicate: "https://kton.dev/v/reviewed",
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

// TestReadJSONEmitsRecordsVerbatim: `about --json` and `by --json` carry the claim BODY, so a
// consumer can decode the payload itself. The prose form answers "which records, roughly"; it does
// not carry the object, and the object is what a claim relates to. A consumer that had to parse the
// line would be parsing a sentence that does not contain the answer.
//
// It used to decode `[{claimId, envelope}]` - the wrapper the command emitted, asserted back at the
// command. A test shaped like the implementation cannot disagree with it, and this one did not: the
// emitted shape was not the one SPEC §12 declares (#124), and this test passed anyway. It now
// decodes the DECLARED shape; TestRecordQueryWireForm covers that contract in full.
func TestReadJSONEmitsRecordsVerbatim(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := claimSpec{
		Subject:   []subjSpec{{URI: "urn:example:doc"}},
		Predicate: "https://kton.dev/v/reviewed",
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
	var got struct {
		Records []struct {
			Payload string `json:"payload"`
		} `json:"records"`
		Summary map[string]map[string]any `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("about --json did not emit JSON: %v\n%s", err, out)
	}
	if len(got.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(got.Records))
	}
	raw, err := base64.StdEncoding.DecodeString(got.Records[0].Payload)
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	// the object must survive: it is absent from the prose form, and it is the destination
	if !bytes.Contains(raw, []byte("urn:example:person")) {
		t.Error("the claim's object did not survive into --json output")
	}
	// The id is still a NAMED field, beside the array rather than inside it (#57): a consumer must
	// not have to assume it is the first hash on a line.
	if len(got.Summary) != 1 {
		t.Errorf("summary holds %d entries, want 1 - the claim id is no longer reachable by name", len(got.Summary))
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
