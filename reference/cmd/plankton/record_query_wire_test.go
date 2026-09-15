package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// SPEC §12 pins TWO wire forms and they are not the same:
//
//	sync            { "records": [ { "seq", "fotonId", "envelope" } … ], "max", "epoch" }
//	record queries  { "records": [ <envelope> … ] }
//
// The record queries answered summary objects with an envelope nested inside, so a consumer decoding
// the declared shape got an array of things that were not envelopes: empty payloadType, no
// signatures, nothing to verify or re-ingest. Only the sync form had a conformance fixture, which is
// why the other half of the clause went unexercised.
func TestRecordQueriesAnswerBareEnvelopes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	for p, b := range map[string]string{in: "a", out: "b"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("c9", 32)}); err != nil {
		t.Fatal(err)
	}
	if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out,
		"--sign", filepath.Join(dir, "k.key"), "--add"}); err != nil {
		t.Fatal(err)
	}
	hash := func(p string) string {
		return strings.TrimSpace(captureStdout(t, func() {
			if err := run("hash", []string{p}); err != nil {
				t.Fatal(err)
			}
		}))
	}
	outHash, inHash := hash(out), hash(in)

	for _, q := range []struct{ cmd, arg string }{
		{"producer", outHash},
		{"uses", inHash},
	} {
		raw := captureStdout(t, func() {
			if err := run(q.cmd, []string{q.arg, "--json"}); err != nil {
				t.Fatalf("%s: %v", q.cmd, err)
			}
		})
		// Decoded through the DECLARED shape - an array of envelopes - which is the whole point:
		// a consumer implementing §12 must be able to do exactly this.
		var got struct {
			Records []core.Envelope `json:"records"`
			Summary map[string]struct {
				Kind string `json:"kind"`
			} `json:"summary"`
		}
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("%s --json is not valid JSON: %v", q.cmd, err)
		}
		if len(got.Records) != 1 {
			t.Fatalf("%s: %d records, want 1", q.cmd, len(got.Records))
		}
		e := got.Records[0]
		if e.PayloadType != core.PayloadType || e.Payload == "" || len(e.Signatures) == 0 {
			t.Errorf("%s: records[0] decoded as an envelope is empty (payloadType=%q, payload=%d bytes, "+
				"%d signatures) - a consumer cannot verify or re-ingest it",
				q.cmd, e.PayloadType, len(e.Payload), len(e.Signatures))
		}
		// It must be the real record, not a shell: the payload has to verify against its own id.
		if _, err := e.PayloadBytes(); err != nil {
			t.Errorf("%s: the envelope's payload does not decode: %v", q.cmd, err)
		}
		// The summary survives the move, keyed by id so nothing has to be index-matched.
		if len(got.Summary) != 1 {
			t.Errorf("%s: summary has %d entries, want one per record", q.cmd, len(got.Summary))
		}
		for _, s := range got.Summary {
			if s.Kind == "" {
				t.Errorf("%s: the summary lost `kind`", q.cmd)
			}
		}
	}
}
