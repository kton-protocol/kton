package federation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kton.dev/plankton/registry"
)

// These tests used to spin up OUR OWN server to exercise OUR OWN client, which proves only that we
// agree with ourselves. §12 is now about the queries and the wire form, with the HTTP binding
// informative (Annex C), and the server has left the repository (#83) - so the client is tested
// against a FIXED DOCUMENT instead. That proves we implement the format.
//
// The fixtures in ../../../reference/testdata/federation/ are the conformance vectors §12 did not
// have. A second implementation can serve them and a third can consume them.
func fixtureServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	root := filepath.Join("..", "..", "..", "reference", "testdata", "federation")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		name, ok := routes[req.URL.Path]
		if !ok {
			http.Error(w, "no fixture for "+req.URL.Path, http.StatusNotFound)
			return
		}
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Errorf("fixture %s: %v", name, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
}

// A sync answer is { records: [ {seq, fotonId, envelope} ... ], max }. The client must read that
// shape from bytes it did not produce.
func TestSyncReadsTheWireForm(t *testing.T) {
	srv := fixtureServer(t, map[string]string{"/sync": "sync-plankton.json"})
	defer srv.Close()

	sr, err := Sync(nil, srv.URL, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(sr.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(sr.Records))
	}
	if sr.Max != 1 {
		t.Errorf("max = %d, want 1 - the cursor is what a mirror persists", sr.Max)
	}
	r := sr.Records[0]
	if r.FotonID == "" || r.Envelope.Payload == "" {
		t.Errorf("record did not survive decoding: %+v", r)
	}
}

// Mirroring is sync + persistence, and a record from the wire must land in a registry that then
// resolves it by hash - the property §12 calls a conflict-free set union.
func TestMirrorPersistsWhatTheWireDelivered(t *testing.T) {
	srv := fixtureServer(t, map[string]string{"/sync": "sync-plankton.json"})
	defer srv.Close()

	dir := t.TempDir()
	local, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	added, _, err := Mirror(nil, local, nil, srv.URL)
	if err != nil {
		t.Fatalf("Mirror: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}

	// Re-open from disk: the record was persisted, not merely held in memory.
	reopened, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 1 {
		t.Errorf("registry holds %d after reopen, want 1", reopened.Len())
	}
	if local.PeerCursor(srv.URL) != 1 {
		t.Errorf("peer cursor = %d, want 1", local.PeerCursor(srv.URL))
	}
}

// A peer that answers with something that is not the wire form must fail loudly. A mirror that
// swallows a malformed answer and reports success is the failure shape this project keeps finding.
func TestAMalformedAnswerIsNotSilentlyAccepted(t *testing.T) {
	for name, body := range map[string]string{
		"not json":    "this is not json",
		"wrong shape": `{"records": "not an array"}`,
		"truncated":   `{"records": [`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		if _, err := Sync(nil, srv.URL, 0); err == nil {
			t.Errorf("%s: Sync accepted it", name)
		}
		srv.Close()
	}
	// And an HTTP error is an error, not an empty batch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Sync(nil, srv.URL, 0); err == nil {
		t.Error("a 500 was read as an empty sync")
	}
	_ = json.Marshal
}
