package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// TestRecordQueryWireForm decodes the shape SPEC §12 DECLARES, not the shape this command happens to
// emit. That distinction is the whole point of the test: `about --json` and `by --json` are the
// `claims(subject | object | signer | predicate)` queries, the clause says the answer is
// `{ "records": [ <envelope> ... ] }`, and what came back was a bare array of `{claimId, envelope}`
// (#124). Wrapping an envelope in a field does not make the element an envelope - a consumer
// decoding the contract got payload="", payloadType="", signatures=0 and could neither verify nor
// re-ingest what it had been handed.
//
// So this test parses into the declared types and then USES the result: it base64-decodes the
// payload and re-derives the claim id from it. A test written against the wrapper would have passed
// throughout, which is why the defect survived - plankton's identical defect (#150) was caught only
// because its sync half had a conformance fixture and its record-query half did not.
func TestRecordQueryWireForm(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("a", 64)
	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"hash":"`+subject+`"}],`+
		`"predicate":"https://kton.dev/v/note","object":{"x":"1"},`+
		`"by":"CN=author","when":"2026-07-16T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "reg")
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := authorClaim(spec, filepath.Join(dir, "k.key"), "", true, reg, true); err != nil {
			t.Fatal(err)
		}
	}))
	t.Setenv("NEKTON_DIR", reg)

	// The declared wire form, and nothing else.
	var got struct {
		Records []core.Envelope           `json:"records"`
		Summary map[string]map[string]any `json:"summary"`
	}
	for _, q := range []struct {
		name string
		run  func() error
	}{
		{"about", func() error { return run("about", []string{subject, "--json"}) }},
		{"by predicate", func() error { return run("by", []string{"predicate", "https://kton.dev/v/note", "--json"}) }},
	} {
		t.Run(q.name, func(t *testing.T) {
			raw := captureStdout(t, func() {
				if err := q.run(); err != nil {
					t.Fatal(err)
				}
			})
			got.Records, got.Summary = nil, nil
			if err := json.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("not valid JSON: %v\n%s", err, raw)
			}
			if len(got.Records) != 1 {
				t.Fatalf("records = %d, want 1 - §12 answers { \"records\": [ <envelope> ... ] }\n%s",
					len(got.Records), raw)
			}
			env := got.Records[0]
			// An element that decodes as an Envelope but carries nothing is exactly the failure the
			// bare-array form produced, and it is silent: json.Unmarshal reports no error.
			if env.PayloadType == "" || env.Payload == "" || len(env.Signatures) == 0 {
				t.Fatalf("the element is not an envelope: payloadType=%q payload=%q signatures=%d",
					env.PayloadType, env.Payload, len(env.Signatures))
			}
			// USE it: the payload must be the canonical Statement, so its digest is the claim id.
			// This is what a consumer does, and what the old shape made impossible.
			payload, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				t.Fatalf("payload is not base64: %v", err)
			}
			if h := core.HashBytes(payload); h != id {
				t.Errorf("re-derived id %s != %s - the returned envelope is not the record it claims", h, id)
			}
			// The claim id is not lost, it is a NAMED field beside the array (#57): a consumer must
			// not have to assume it is the first hash on a line, nor re-derive it to know it.
			if _, ok := got.Summary[id]; !ok {
				t.Errorf("summary has no entry for %s; keys = %v", id, keysOf(got.Summary))
			}
			if by := got.Summary[id]["by"]; by != "CN=author" {
				t.Errorf("summary by = %v, want CN=author", by)
			}
			// Never `signer`: the keyid is self-declared and not covered by the signature.
			if _, bad := got.Summary[id]["signer"]; bad {
				t.Error("summary calls a self-declared keyid `signer` - that reads as verified identity")
			}
		})
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
