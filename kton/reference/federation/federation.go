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

// This package ships the federation CLIENT and no server. The queries of SPEC §12 are normative;
// the HTTP binding that carries them is not (Annex C), and a specification of a protocol is not a
// place to distribute a network service: a listening socket brings authentication, transport
// security, rate limiting and request bounds with it, and those belong to a deployment. Writing a
// server over the §12 table is a small amount of code in any language, and
// reference/testdata/federation/ fixes the bytes it must produce (#83).


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
