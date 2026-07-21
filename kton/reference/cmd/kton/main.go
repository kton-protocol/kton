// Command kton is the reference COCKPIT: it conducts plankton (reproducible fotons) and
// nekton (signed claims) but reimplements neither. Everything kton does is a call into a
// kernel package - delete kton and every operation is still runnable directly. kton exists
// only to hold the surface deliberately kept OUT of the kernels so they stay clean and
// WebAssembly-compilable: the network (federation serve/mirror), the transparency log
// (Rekor anchoring), and optional byte pinning (the blob store). No kernel imports net/http;
// this binary is the one place ports are opened.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
	"kton.dev/kton/federation"
	preg "kton.dev/plankton/registry"

	nreg "kton.dev/nekton/registry"
)

const usage = `kton - the cockpit that conducts plankton + nekton (reimplements nothing)

usage:
  kton serve  plankton [addr]              serve the plankton federation API (default :8787)
  kton serve  nekton   [addr]              serve the nekton   federation API (default :8788)
  kton mirror plankton <peer> [--pin]      pull+persist a peer plankton registry
  kton mirror nekton   <peer>              pull+persist a peer nekton   registry
  kton anchor <envelope.dsse.json> <pubkey.pub|hex>
                                           anchor a signed record in the Rekor transparency log
  kton pin    <file>                       pin a file's bytes into the plankton blob store
  kton blob   <sha256:...>                 is this content pinned locally?
  kton fetch  <sha256:...>                 resolve content via signed nekton located-at claims,
                                           dereference the URIs, verify sha256, and pin
  kton man                                 print the embedded manual page (roff)

  <peer> is a URL (http://host:port, needs a running 'kton serve') OR a local registry
  directory (e.g. ../session-1/plankton-data) - a local peer is read directly, no port.
  --pin (plankton, URL peer only) also fetches and re-serves the verified bytes.

env:
  PLANKTON_DIR   plankton registry dir (default ./plankton-data)
  NEKTON_DIR     nekton   registry dir (default ./nekton-data)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func planktonDir() string {
	if d := os.Getenv("PLANKTON_DIR"); d != "" {
		return d
	}
	return "./plankton-data"
}

func nektonDir() string {
	if d := os.Getenv("NEKTON_DIR"); d != "" {
		return d
	}
	return "./nekton-data"
}

func readEnvelope(path string) (core.Envelope, error) {
	var env core.Envelope
	b, err := os.ReadFile(path)
	if err != nil {
		return env, err
	}
	return env, json.Unmarshal(b, &env)
}

// isURL reports whether a peer reference is an HTTP endpoint (vs a local directory).
func isURL(peer string) bool {
	return strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://")
}

func run(cmd string, args []string) error {
	switch cmd { // help/version in COMMAND position (not just as a flag) should not be "unknown command"
	case "--help", "-h", "help":
		fmt.Print(usage)
		return nil
	case "--version", "-v", "version":
		fmt.Println("kton 0.1 (reference)")
		return nil
	}
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Print(usage)
			return nil
		}
	}
	switch cmd {
	case "man":
		fmt.Print(manPage)
		return nil
	case "serve":
		if len(args) < 1 {
			return fmt.Errorf("usage: kton serve <plankton|nekton> [addr]")
		}
		addr := ""
		if len(args) >= 2 {
			addr = args[1]
		}
		switch args[0] {
		case "plankton":
			if addr == "" {
				addr = ":8787"
			}
			fmt.Printf("plankton federation API on %s  (registry %s)\n", addr, planktonDir())
			return http.ListenAndServe(addr, federation.NewServer(planktonDir()))
		case "nekton":
			if addr == "" {
				addr = ":8788"
			}
			fmt.Printf("nekton federation API on %s  (registry %s)\n", addr, nektonDir())
			return http.ListenAndServe(addr, nektonServer(nektonDir()))
		default:
			return fmt.Errorf("usage: kton serve <plankton|nekton> [addr]")
		}

	case "mirror":
		if len(args) < 2 {
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <peer> [--pin]")
		}
		which, peer := args[0], strings.TrimRight(args[1], "/")
		pin := false
		for _, a := range args[2:] {
			if a == "--pin" {
				pin = true
			}
		}
		switch which {
		case "plankton":
			return mirrorPlankton(planktonDir(), peer, pin)
		case "nekton":
			return mirrorNekton(nektonDir(), peer)
		default:
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <peer> [--pin]")
		}

	case "anchor":
		if len(args) != 2 {
			return fmt.Errorf("usage: kton anchor <envelope.dsse.json> <pubkey.pub|hex>")
		}
		return anchor(args[0], args[1])

	case "pin":
		if len(args) != 1 {
			return fmt.Errorf("usage: kton pin <file>")
		}
		b, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		bs, err := blobstore.Open(filepath.Join(planktonDir(), federation.BlobsSubdir))
		if err != nil {
			return err
		}
		h, err := bs.Put(b)
		if err != nil {
			return err
		}
		fmt.Printf("pinned %s  (%d bytes)\n", h, len(b))
		return nil

	case "blob":
		if len(args) != 1 {
			return fmt.Errorf("usage: kton blob <sha256:...>")
		}
		h := normalizeHash(args[0]) // accept bare-hex / UPPERCASE / whitespace spellings of the same hash
		bs, err := blobstore.Open(filepath.Join(planktonDir(), federation.BlobsSubdir))
		if err != nil {
			return err
		}
		if bs.Has(h) {
			// Do not trust the content-addressed FILENAME: read the bytes back (blobstore.Get
			// re-hashes and errors on a mismatch), so a bit-rotted blob is reported as corrupt, not
			// PINNED. `Has` alone only checks the file exists - a present-and-good status line that
			// never re-hashes would be a lie.
			b, err := bs.Get(h)
			if err != nil {
				fmt.Printf("CORRUPT %s  (%v)\n", h, err)
				os.Exit(1)
			}
			fmt.Printf("PINNED %s  (%d bytes, re-hashed OK)\n", h, len(b))
			return nil
		}
		fmt.Printf("absent %s\n", h)
		os.Exit(1)
		return nil

	case "fetch":
		if len(args) != 1 {
			return fmt.Errorf("usage: kton fetch <sha256:...>")
		}
		return fetch(args[0])

	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

// mirrorPlankton pulls a peer plankton registry into the local one. A URL peer uses the HTTP
// federation client (optionally pinning bytes); a local-directory peer is read directly - the
// zero-ceremony path the lab uses for cross-session discovery (no server, no port).
func mirrorPlankton(localDir, peer string, pin bool) error {
	local, err := preg.Open(localDir)
	if err != nil {
		return err
	}
	if isURL(peer) {
		var bs *blobstore.Store
		if pin {
			if bs, err = blobstore.Open(filepath.Join(localDir, federation.BlobsSubdir)); err != nil {
				return err
			}
		}
		added, pinned, err := federation.Mirror(nil, local, bs, peer)
		if err != nil {
			return err
		}
		fmt.Printf("mirrored %s: %d new record(s), %d blob(s) pinned; registry holds %d fotons\n",
			peer, added, pinned, local.Len())
		return nil
	}
	if fi, err := os.Stat(peer); err != nil || !fi.IsDir() {
		return fmt.Errorf("peer registry %q does not exist (nothing to mirror)", peer)
	}
	src, err := preg.Open(peer)
	if err != nil {
		return fmt.Errorf("open local peer %s: %w", peer, err)
	}
	envs := make([]core.Envelope, 0, len(src.Records(0)))
	for _, rec := range src.Records(0) {
		envs = append(envs, rec.Envelope)
	}
	added, skipped := settleAdd(local.Add, envs)
	fmt.Printf("mirrored %s: %d new, %d skipped; registry holds %d fotons\n", peer, added, skipped, local.Len())
	return nil
}

// mirrorNekton is the nekton counterpart. Claims keep their original signatures - mirroring is
// not confirming (SPEC §6). The settle loop tolerates order-free delivery: a scoped child that
// arrives before its seed is retried across passes, so a subnekton federates intact.
func mirrorNekton(localDir, peer string) error {
	local, err := nreg.Open(localDir)
	if err != nil {
		return err
	}
	if isURL(peer) {
		return nektonHTTPMirror(local, peer)
	}
	if fi, err := os.Stat(peer); err != nil || !fi.IsDir() {
		return fmt.Errorf("peer registry %q does not exist (nothing to mirror)", peer)
	}
	src, err := nreg.Open(peer)
	if err != nil {
		return fmt.Errorf("open local peer %s: %w", peer, err)
	}
	// RawRecords (not Records) so the peer's own UNRESOLVED claims travel too: a claim whose seed/prev
	// lives in a THIRD peer is an orphan in this one, but mirroring must carry it so a later mirror of
	// that third peer resolves it. Otherwise mirror order changes the result (B-then-A drops a chained
	// claim), violating "mirror is an optimization, not a result".
	raw := src.RawRecords()
	envs := make([]core.Envelope, 0, len(raw))
	for _, rec := range raw {
		envs = append(envs, rec.Envelope)
	}
	added, skipped := settleAdd(local.Add, envs)
	fmt.Printf("mirrored %s: %d new, %d deferred (unresolved, persisted for a later mirror); registry holds %d claim(s)\n", peer, added, skipped, local.Len())
	return nil
}

// settleAdd feeds envelopes into a registry's Add, retrying deferrable failures across passes
// (a nekton scoped child settles once its seed + prev are indexed) and skipping records that
// never become valid - so one malformed record can never wedge replication. Works for both
// kernels because both expose the same Add signature.
func settleAdd(add func(core.Envelope) (string, bool, error), envs []core.Envelope) (added, skipped int) {
	pending := envs
	for {
		progress := false
		var next []core.Envelope
		for _, e := range pending {
			_, isNew, err := add(e)
			if err != nil {
				next = append(next, e)
				continue
			}
			if isNew {
				added++
			}
			progress = true
		}
		pending = next
		if !progress {
			break
		}
	}
	return added, len(pending)
}

// --- nekton federation server + HTTP mirror (moved verbatim out of the nekton kernel) --------
// SPEC §6: claims by subject/object/signer/predicate + sync/mirror. This is cockpit surface,
// not kernel - it opens a port, so it lives here.

type syncResp struct {
	Records []nreg.Record `json:"records"`
	Max     int           `json:"max"`
}

func nektonServer(d string) http.Handler {
	mux := http.NewServeMux()
	open := func(w http.ResponseWriter) (*nreg.Registry, bool) {
		r, err := nreg.Open(d)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, false
		}
		return r, true
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		r, ok := open(w)
		if !ok {
			return
		}
		writeJSON(w, map[string]any{"ok": true, "claims": r.Len(), "maxSeq": r.MaxSeq()})
	})
	mux.HandleFunc("/claims", func(w http.ResponseWriter, req *http.Request) {
		r, ok := open(w)
		if !ok {
			return
		}
		q := req.URL.Query()
		var recs []nreg.Record
		switch {
		case q.Get("subject") != "":
			recs = r.About(q.Get("subject"))
		case q.Get("object") != "":
			recs = r.ByObject(q.Get("object"))
		case q.Get("signer") != "":
			recs = r.BySigner(q.Get("signer"))
		case q.Get("predicate") != "":
			recs = r.ByPredicate(q.Get("predicate"))
		}
		writeJSON(w, map[string]any{"records": envsOf(recs)})
	})
	mux.HandleFunc("/sync", func(w http.ResponseWriter, req *http.Request) {
		r, ok := open(w)
		if !ok {
			return
		}
		since, _ := strconv.Atoi(req.URL.Query().Get("since"))
		recs := r.Records(since)
		if recs == nil {
			recs = []nreg.Record{}
		}
		writeJSON(w, syncResp{Records: recs, Max: r.MaxSeq()})
	})
	return mux
}

func envsOf(recs []nreg.Record) []core.Envelope {
	out := make([]core.Envelope, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.Envelope)
	}
	return out
}

func nektonHTTPMirror(local *nreg.Registry, peer string) error {
	resp, err := http.Get(fmt.Sprintf("%s/sync?since=%d", peer, local.PeerCursor(peer)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer %s: %s", peer, resp.Status)
	}
	var sr syncResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return err
	}
	envs := make([]core.Envelope, 0, len(sr.Records))
	for _, rec := range sr.Records {
		envs = append(envs, rec.Envelope)
	}
	added, skipped := settleAdd(local.Add, envs)
	if err := local.SetPeerCursor(peer, sr.Max); err != nil {
		return err
	}
	fmt.Printf("mirrored %s: %d new, %d skipped; registry holds %d claim(s)\n", peer, added, skipped, local.Len())
	return nil
}
