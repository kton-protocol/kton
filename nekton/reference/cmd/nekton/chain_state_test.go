package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestChainStateIsNeverAssertedWithoutLooking: `verify` and `show` report what this store
// established about a claim's chain. The report used to be derived from a single string - empty
// meant "not deferred" - and a claim read from a FILE leaves that string empty, so it printed
//
//	chain:           RESOLVED - this store holds what the claim depends on
//	"chain": "resolved"
//
// for a scoped claim naming a seed the store did not have, against a registry holding zero records.
// Nothing had been looked up.
//
// SPEC §8.1's read-path boundary is precisely this: presence is not a check, and a kernel's own
// output MUST NOT carry a field that reads as a verification verdict. UNCHECKED is therefore a first
// class state and the default, and this test pins all three.
func TestChainStateIsNeverAssertedWithoutLooking(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("9a", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	reg := filepath.Join(dir, "reg")
	t.Setenv("NEKTON_DIR", reg)

	// A seed authored to a FILE, never added: the scope exists, this store does not hold it.
	seedFile := filepath.Join(dir, "seed.dsse.json")
	seedID := strings.TrimSpace(captureStdout(t, func() {
		if err := run("seed", []string{"sc", "--sign", key, "-o", seedFile, "--print-id"}); err != nil {
			t.Fatal(err)
		}
	}))

	spec := filepath.Join(dir, "c.json")
	if err := os.WriteFile(spec, []byte(`{"subject":[{"uri":"urn:x"}],`+
		`"predicate":"https://kton.dev/v/note","object":{"a":"1"},"by":"CN=t",`+
		`"when":"2026-07-16T00:00:00Z","scope":"`+seedID+`","prev":"`+seedID+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	claimFile := filepath.Join(dir, "scoped.dsse.json")
	if err := run("claim", []string{spec, key, claimFile}); err != nil {
		t.Fatal(err)
	}

	chainOf := func(t *testing.T, arg string) string {
		t.Helper()
		raw := captureStdout(t, func() {
			if err := run("show", []string{arg, "--json"}); err != nil {
				t.Fatal(err)
			}
		})
		var got struct {
			Chain string `json:"chain"`
		}
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, raw)
		}
		return got.Chain
	}

	// 1. A FILE: never looked up here. The one the regression was about.
	if c := chainOf(t, claimFile); c != "unchecked" {
		t.Errorf("a claim read from a file reports chain=%q - this store was never asked about its "+
			"scope or prev, so anything but \"unchecked\" is a verdict it did not earn", c)
	}

	// 2. Ingested while its seed is missing: DEFERRED - established, not assumed.
	if err := run("add", []string{claimFile}); err != nil {
		t.Fatalf("add: %v", err)
	}
	claimID := strings.TrimSpace(captureStdout(t, func() {
		if err := run("records", []string{"--json"}); err != nil {
			t.Fatal(err)
		}
	}))
	var feed struct {
		Records []struct {
			ClaimID string `json:"claimId"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(claimID), &feed); err != nil || len(feed.Records) == 0 {
		t.Fatalf("cannot find the ingested claim: %v", err)
	}
	id := feed.Records[0].ClaimID
	if c := chainOf(t, id); c != "deferred" {
		t.Errorf("chain=%q for a claim whose seed has not arrived, want deferred", c)
	}

	// 3. Seed arrives: RESOLVED, and now it is earned - the claim is in the index, so checkChain passed.
	if err := run("add", []string{seedFile}); err != nil {
		t.Fatalf("adding the seed: %v", err)
	}
	if c := chainOf(t, id); c != "resolved" {
		t.Errorf("chain=%q after the seed arrived, want resolved", c)
	}
}
