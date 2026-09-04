package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// testdata/federation/ holds the §12 conformance vectors: the exact document a participant must
// answer `sync(since)` with. Until now the only test over them lived in the deleted kton HTTP
// federation CLIENT - it proved we could READ the wire form. With the client gone (#101, no caller
// ever), what has to be protected is the other direction: that `plankton records --json` still
// EMITS it. That is the direction that matters now, because stdout is the binding the reference
// implementation actually offers (§12, Annex C is informative).
//
// The comparison is over the PARSED DOCUMENT, not over bytes, and that is deliberate rather than
// lax. printJSON marshals a map[string]any, so Go emits the keys sorted and `max` comes first,
// while the fixture keeps the wire order with `records` first. An earlier comment in records.go
// claimed the two were byte-identical and "cannot drift"; both halves were wrong - they are not the
// same bytes, and nothing compared them at all. This test is what makes the second half true.
func TestRecordsJSONEmitsTheFixtureWireForm(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "federation", "sync-plankton.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read the conformance vector: %v", err)
	}
	var want struct {
		Records []struct {
			Seq      int             `json:"seq"`
			FotonID  string          `json:"fotonId"`
			Envelope json.RawMessage `json:"envelope"`
		} `json:"records"`
		Max int `json:"max"`
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("the conformance vector is not the documented shape: %v", err)
	}
	if len(want.Records) == 0 {
		t.Fatal("the conformance vector holds no records - it cannot witness anything")
	}

	// Ingest the fixture's own envelopes into a fresh registry, then ask for them back. A round
	// trip, so the test needs no key material and cannot drift from whatever the fixture was signed
	// with.
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	for i, rec := range want.Records {
		p := filepath.Join(dir, "env.json")
		if err := os.WriteFile(p, rec.Envelope, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := run("add", []string{p}); err != nil {
			t.Fatalf("record %d from the conformance vector was refused at ingest: %v", i, err)
		}
	}

	out := captureStdout(t, func() {
		if err := run("records", []string{"--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var got struct {
		Records []struct {
			Seq      int             `json:"seq"`
			FotonID  string          `json:"fotonId"`
			Envelope json.RawMessage `json:"envelope"`
		} `json:"records"`
		Max int `json:"max"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("records --json is not parseable as the wire form: %v\n%s", err, out)
	}

	if len(got.Records) != len(want.Records) {
		t.Fatalf("records = %d, want %d", len(got.Records), len(want.Records))
	}
	if got.Max != want.Max {
		t.Errorf("max = %d, want %d - the cursor is what a peer persists and passes back as --since",
			got.Max, want.Max)
	}
	for i := range want.Records {
		w, g := want.Records[i], got.Records[i]
		if g.FotonID != w.FotonID {
			t.Errorf("record %d: fotonId = %q, want %q", i, g.FotonID, w.FotonID)
		}
		if g.Seq != w.Seq {
			t.Errorf("record %d: seq = %d, want %d", i, g.Seq, w.Seq)
		}
		// The envelope must survive as the SAME document - signatures included, since a mirror
		// re-serves exactly these bytes to the next peer.
		var we, ge any
		if err := json.Unmarshal(w.Envelope, &we); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(g.Envelope, &ge); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(we, ge) {
			t.Errorf("record %d: the envelope changed crossing the registry\n want %s\n  got %s",
				i, w.Envelope, g.Envelope)
		}
	}
}
