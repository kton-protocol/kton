package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

// The last three gaps in the machine-readable surface (#74). `reuse` mattered most: its hit count
// answers "was this computation asked before?", and kton-examples 16-reuse-cache read it with a sed
// over the prose line - and documented doing so, which made an output-format change a silent break
// in a published example.
func TestReuseAndAddMachineSurface(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	for p, b := range map[string]string{in: "a", out: "b"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("5a", 32)}); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "f.dsse.json")
	if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out,
		"--sign", filepath.Join(dir, "k.key"), "-o", env}); err != nil {
		t.Fatal(err)
	}

	// add --print-id: the bare id and nothing else on stdout, same contract as author/claim/seed.
	id := strings.TrimSpace(captureStdout(t, func() {
		if err := run("add", []string{env, "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(id) {
		t.Errorf("add --print-id stdout = %q; want one bare id", id)
	}
	// It promises ONE id. Two envelopes would print several and quietly break ID=$(plankton add …).
	if err := run("add", []string{env, env, "--print-id"}); err == nil {
		t.Error("--print-id accepted two envelopes")
	}

	var got struct {
		ActionKey string `json:"actionKey"`
		Hit       bool   `json:"hit"`
		Hits      []struct {
			FotonID        string `json:"fotonId"`
			DeclaredSigner string `json:"declaredSigner"`
			Verified       bool   `json:"verified"`
		} `json:"hits"`
	}
	raw := captureStdout(t, func() {
		if err := run("reuse", []string{env, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("reuse --json is not valid JSON: %v\n%s", err, raw)
	}
	if !got.Hit || len(got.Hits) != 1 || got.Hits[0].FotonID != id {
		t.Errorf("reuse --json = %+v; want one hit naming %s", got, id)
	}
	// A cache key binds inputs+protocol, not signer: hits COMPETE, and the keyid is the envelope's
	// unauthenticated hint. That has to be on the record a machine reads, not only in a stderr note.
	if got.Hits[0].Verified {
		t.Error("a cache hit reported verified - reuse verifies nothing")
	}
	if got.Hits[0].DeclaredSigner == "" {
		t.Error("the declared signer is missing; a consumer cannot pick a signer it trusts")
	}
}
