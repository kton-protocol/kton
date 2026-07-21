// Package federation exposes a registry over HTTP (spec §12) and pulls/mirrors peers.
// Registries are peers that overlay by hash; sync is set-reconciliation of an append log;
// mirroring is sync + persistence. Bytes are never transferred - only metadata (records).
package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// BlobsSubdir is where an instance keeps optionally-pinned bytes under its registry dir.
const BlobsSubdir = "blobs"

// EnvList is the response for producer/uses/ray/attestations queries.
type EnvList struct {
	Records []core.Envelope `json:"records"`
}

// SyncResp is the response for the sync feed.
type SyncResp struct {
	Records []registry.Record `json:"records"`
	Max     int               `json:"max"`
}

// NewServer returns an HTTP handler serving the registry rooted at dir. Handlers re-open
// the registry per request, so a concurrently-running `add`/`mirror` is reflected live.
func NewServer(dir string) http.Handler {
	mux := http.NewServeMux()

	withReg := func(w http.ResponseWriter) (*registry.Registry, bool) {
		r, err := registry.Open(dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, false
		}
		return r, true
	}
	envsFor := func(r *registry.Registry, ids []string) EnvList {
		out := EnvList{Records: []core.Envelope{}}
		for _, id := range ids {
			if env, ok := r.Envelope(id); ok {
				out.Records = append(out.Records, env)
			}
		}
		return out
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		r, ok := withReg(w)
		if !ok {
			return
		}
		writeJSON(w, map[string]any{"ok": true, "fotons": r.Len(), "maxSeq": r.MaxSeq()})
	})

	mux.HandleFunc("/producer", func(w http.ResponseWriter, req *http.Request) {
		r, ok := withReg(w)
		if !ok {
			return
		}
		writeJSON(w, envsFor(r, r.Producer(req.URL.Query().Get("hash"))))
	})

	mux.HandleFunc("/uses", func(w http.ResponseWriter, req *http.Request) {
		r, ok := withReg(w)
		if !ok {
			return
		}
		writeJSON(w, envsFor(r, r.Uses(req.URL.Query().Get("hash"))))
	})

	mux.HandleFunc("/ray", func(w http.ResponseWriter, req *http.Request) {
		r, ok := withReg(w)
		if !ok {
			return
		}
		writeJSON(w, envsFor(r, r.Lineage(req.URL.Query().Get("hash"))))
	})

	// /blob serves optionally-pinned bytes (a mirror that pinned is itself a byte source).
	mux.HandleFunc("/blob", func(w http.ResponseWriter, req *http.Request) {
		hash := req.URL.Query().Get("hash")
		bs, err := blobstore.Open(filepath.Join(dir, BlobsSubdir))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, err := bs.Get(hash)
		if err != nil {
			http.Error(w, "not pinned here", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/sync", func(w http.ResponseWriter, req *http.Request) {
		r, ok := withReg(w)
		if !ok {
			return
		}
		since, _ := strconv.Atoi(req.URL.Query().Get("since"))
		recs := r.Records(since)
		if recs == nil {
			recs = []registry.Record{}
		}
		writeJSON(w, SyncResp{Records: recs, Max: r.MaxSeq()})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Sync pulls the records a peer has beyond `since`.
func Sync(client *http.Client, peerURL string, since int) (*SyncResp, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(fmt.Sprintf("%s/sync?since=%d", peerURL, since))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer %s: %s: %s", peerURL, resp.Status, string(b))
	}
	var sr SyncResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, err
	}
	return &sr, nil
}

// GetBlob fetches and verifies the bytes for a hash from a peer's /blob endpoint.
// Returns (nil, nil) if the peer does not have it pinned (404).
func GetBlob(client *http.Client, peerURL, hash string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(fmt.Sprintf("%s/blob?hash=%s", peerURL, hash))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer %s blob: %s", peerURL, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if got := core.HashBytes(b); got != hash {
		return nil, fmt.Errorf("peer served wrong bytes: wanted %s, got %s", hash, got)
	}
	return b, nil
}

// Mirror pulls everything new from a peer into the local registry and advances the peer
// cursor. Idempotent. Mirroring != confirming: envelopes keep their original signatures,
// re-verifiable locally. If bs is non-nil, also PIN the bytes of every file referenced by
// the mirrored fotons that the peer can serve - verified against their hash. Returns the
// count of newly-added records and newly-pinned blobs.
func Mirror(client *http.Client, r *registry.Registry, bs *blobstore.Store, peerURL string) (added, pinned int, err error) {
	sr, err := Sync(client, peerURL, r.PeerCursor(peerURL))
	if err != nil {
		return 0, 0, err
	}
	hashes := map[string]bool{}
	skipped := 0
	for _, rec := range sr.Records {
		_, isNew, err := r.Add(rec.Envelope)
		if err != nil {
			if errors.Is(err, registry.ErrPersist) {
				// A LOCAL persistence failure (disk full, permission, crash mid-write) - NOT a record
				// rejected on its merits. Abort WITHOUT advancing the cursor, so the next mirror re-pulls
				// this valid record instead of silently, permanently dropping it (round-2 H-e).
				return added, pinned, err
			}
			// SPEC 12: a record that cannot be ingested - foreign/non-foton, or an ingest rejection (bad
			// signature, protocol.ref mismatch, non-canonical payload, ambiguous relpath) - is SKIPPED, and
			// the peer cursor still advances below, so one malformed or HOSTILE record cannot wedge
			// replication. Mirrors the nekton settle-and-advance path; `verify` still adjudicates locally.
			if !errors.Is(err, registry.ErrNotFoton) {
				skipped++
			}
			continue
		}
		if isNew {
			added++
		}
		if bs != nil {
			if f, id, _ := tryFoton(rec.Envelope); id != "" && f != nil {
				for _, ref := range append(append([]core.FileRef{}, f.Inputs...), f.Outputs...) {
					hashes[ref.Hash] = true
				}
			}
		}
	}
	if bs != nil {
		for h := range hashes {
			if bs.Has(h) {
				continue
			}
			b, err := GetBlob(client, peerURL, h)
			if err != nil || b == nil {
				continue // peer can't serve it, or a transient fetch error: skip the pin, never wedge the cursor
			}
			if err := bs.PutVerified(h, b); err != nil {
				continue // hash mismatch / write error: skip this blob, keep syncing
			}
			pinned++
		}
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "mirror: skipped %d un-ingestable record(s) from %s (cursor advanced; SPEC 12)\n", skipped, peerURL)
	}
	if err := r.SetPeerCursor(peerURL, sr.Max); err != nil {
		return added, pinned, err
	}
	return added, pinned, nil
}

func tryFoton(env core.Envelope) (*core.Foton, string, error) {
	st, err := env.Statement()
	if err != nil || st.PredicateType != core.PredicateFoton {
		return nil, "", err
	}
	f, err := st.ToFoton()
	if err != nil {
		return nil, "", err
	}
	id, err := f.FotonID()
	return f, id, err
}
