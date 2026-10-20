package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// `author --condition` marks a step that read what no input pins. The mark is v1 only, and every
// face that reports on the record shows it.
func TestConditionalFotonThroughTheCLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	q, snap, report := filepath.Join(dir, "query.sql"), filepath.Join(dir, "snapshot.csv"), filepath.Join(dir, "report.txt")
	for p, b := range map[string]string{q: "select *", snap: "rows", report: "summary"} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("5a", 32)}); err != nil {
		t.Fatal(err)
	}
	k := filepath.Join(dir, "k.key")
	if err := run("author", []string{"--cmd", "psql -f query.sql", "--in", q, "--out", snap,
		"--condition", "database=prod", "--sign", k, "-o", filepath.Join(dir, "x.json")}); err == nil {
		t.Error("--condition without --statement v1 was signed")
	}
	env := filepath.Join(dir, "snap.dsse.json")
	if err := run("author", []string{"--statement", "v1", "--cmd", "psql -f query.sql", "--in", q, "--out", snap,
		"--condition", "network", "--condition", "database=prod", "--sign", k, "-o", env, "--add"}); err != nil {
		t.Fatal(err)
	}
	// Downstream of the capture: an ordinary foton, whose lineage rests on the conditional one.
	if err := run("author", []string{"--statement", "v1", "--cmd", "summarize", "--in", snap, "--out", report,
		"--sign", k, "--add"}); err != nil {
		t.Fatal(err)
	}

	if out := captureStdout(t, func() { _ = run("show", []string{env}) }); !strings.Contains(out, "CONDITIONAL") ||
		!strings.Contains(out, "database = prod") {
		t.Errorf("show does not mark the conditional foton:\n%s", out)
	}
	var reuse struct {
		Hits []struct {
			Conditions []core.Condition `json:"conditions"`
		} `json:"hits"`
	}
	raw := captureStdout(t, func() {
		if err := run("reuse", []string{env, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &reuse); err != nil || len(reuse.Hits) != 1 ||
		len(reuse.Hits[0].Conditions) != 2 || reuse.Hits[0].Conditions[0].Kind != "database" {
		t.Errorf("reuse --json does not carry the conditions in canonical order (%v):\n%s", err, raw)
	}
	var lin struct {
		DependsOnConditional []string `json:"dependsOnConditional"`
	}
	raw = captureStdout(t, func() {
		if err := run("lineage", []string{core.HashBytes([]byte("summary")), "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(raw), &lin); err != nil || len(lin.DependsOnConditional) != 1 {
		t.Errorf("lineage --json does not say it rests on the conditional foton (%v):\n%s", err, raw)
	}
}
