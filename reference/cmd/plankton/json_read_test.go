package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The read surface used to be prose only, so a consumer had to regex ids out of it and redact line
// by line - resting on the assumption that a record's own id is the FIRST hash on its line. That
// held, was guaranteed nowhere, and no test protected it (#57). Reorder one output line so another
// hash comes first and the consumer silently mislabels a record: green, no symptom.
//
// --json removes the assumption rather than shoring it up: the id is a named field.
func TestReadSurfaceEmitsJSONWithNamedIDs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))

	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out, "--sign", key, "--add"}); err != nil {
		t.Fatal(err)
	}

	outHash := captureStdout(t, func() {
		if err := run("hash", []string{out}); err != nil {
			t.Fatal(err)
		}
	})
	outHash = strings.TrimSpace(outHash)

	t.Run("producer", func(t *testing.T) {
		var got struct {
			Relation string `json:"relation"`
			Query    string `json:"query"`
			Records  []struct {
				FotonID string `json:"fotonId"`
				Kind    string `json:"kind"`
			} `json:"records"`
		}
		raw := captureStdout(t, func() {
			if err := run("producer", []string{outHash, "--json"}); err != nil {
				t.Fatal(err)
			}
		})
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("not valid JSON: %v\n%s", err, raw)
		}
		if got.Relation != "producer" || got.Query != outHash {
			t.Errorf("relation/query = %q/%q", got.Relation, got.Query)
		}
		if len(got.Records) != 1 || !strings.HasPrefix(got.Records[0].FotonID, "sha256:") {
			t.Errorf("records = %+v; want one record carrying its id as a NAMED field", got.Records)
		}
	})

	t.Run("reproductions marks forgeability per record", func(t *testing.T) {
		var got struct {
			Trust     string `json:"trust"`
			Producers []struct {
				FotonID  string `json:"fotonId"`
				Verified bool   `json:"verified"`
			} `json:"producers"`
		}
		raw := captureStdout(t, func() {
			if err := run("reproductions", []string{outHash, "--json"}); err != nil {
				t.Fatal(err)
			}
		})
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("not valid JSON: %v\n%s", err, raw)
		}
		if got.Trust != "self-declared" {
			t.Errorf("trust = %q; want self-declared without --trust-keys", got.Trust)
		}
		// Without --trust-keys the count is forgeable. That has to be visible ON the record a machine
		// acts on, not only in a stderr warning it may never read.
		for _, p := range got.Producers {
			if p.Verified {
				t.Errorf("%s reported verified without --trust-keys", p.FotonID)
			}
		}
	})
}
