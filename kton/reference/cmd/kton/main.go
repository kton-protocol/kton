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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"kton.dev/kton/federation"
	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
	preg "kton.dev/plankton/registry"

	nreg "kton.dev/nekton/registry"
)

const usage = `kton - the cockpit that conducts plankton + nekton (reimplements nothing)

usage:
  kton mirror plankton <peer> [--pin]      pull+persist a peer plankton registry
  kton mirror nekton   <peer> [--with-material]  pull+persist a peer nekton registry
      --with-material    also make this copy of the EVIDENCE complete: ask the peer about every
                         claim held, not the last sync batch. Material is attached out of band
                         and after the fact, so a batch would miss it (SPEC §8.1).
  kton anchor <envelope.dsse.json> <pubkey.pub|hex> [--store]
                                           anchor a signed record in the Rekor transparency log
      --store            record the verified entry as §8.1 verification material ON the record,
                         which is what §13 asks for - otherwise the proof is only printed, and a
                         year from now verification depends on the service still answering
  kton pin    <file>                       pin a file's bytes into the plankton blob store
  kton blob   <sha256:...>                 is this content pinned locally?
  kton fetch  <sha256:...> --trust-keys <dir> [--allow-local]
                                           resolve content via located-at claims signed by a key
                                           you named, dereference, verify sha256, and pin.
      --allow-local      also accept file:// and addresses on this host/network. A signature
                         about CONTENT cannot vouch for a path on your machine.
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
		fmt.Println("kton 0.2 (reference)")
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
	case "mirror":
		if len(args) < 2 {
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <peer> [--pin] [--with-material]")
		}
		which, peer := args[0], strings.TrimRight(args[1], "/")
		pin, withMaterial := false, false
		for _, a := range args[2:] {
			switch a {
			case "--pin":
				pin = true
			case "--with-material":
				withMaterial = true
			default:
				return fmt.Errorf("unknown flag %q", a)
			}
		}
		switch which {
		case "plankton":
			if withMaterial {
				return fmt.Errorf("--with-material applies to a nekton mirror (verification material attaches to claims here)")
			}
			return mirrorPlankton(planktonDir(), peer, pin)
		case "nekton":
			if err := mirrorNekton(nektonDir(), peer); err != nil {
				return err
			}
			if withMaterial {
				return pullMaterial(nektonDir(), peer)
			}
			return nil
		default:
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <peer> [--pin] [--with-material]")
		}

	case "anchor":
		anchorArgs, store := []string{}, false
		for _, a := range args {
			if a == "--store" {
				store = true
				continue
			}
			anchorArgs = append(anchorArgs, a)
		}
		if len(anchorArgs) != 2 {
			return fmt.Errorf("usage: kton anchor <envelope.dsse.json> <pubkey.pub|hex> [--store]\n" +
				"  --store records the verified entry as verification material on the record (SPEC §8.1, §13)")
		}
		return anchor(anchorArgs[0], anchorArgs[1], store)

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
		var fHash, fTrust string
		fLocal := false
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--trust-keys":
				i++
				if i >= len(args) {
					return fmt.Errorf("--trust-keys expects a directory of *.pub keys")
				}
				fTrust = args[i]
			case "--allow-local":
				fLocal = true
			default:
				if strings.HasPrefix(args[i], "--") {
					return fmt.Errorf("unknown flag %q", args[i])
				}
				fHash = args[i]
			}
		}
		if fHash == "" {
			return fmt.Errorf("usage: kton fetch <sha256:...> --trust-keys <dir> [--allow-local]\n" +
				"  a located-at claim is a SUGGESTION from whoever signed it. Dereferencing one is a\n" +
				"  request from this host - and for file://, a read of this disk - which the hash check\n" +
				"  afterwards cannot undo. So it happens only for signers you named.")
		}
		return fetch(fHash, fTrust, fLocal)

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

// pullMaterial makes this copy of the evidence COMPLETE: it asks the peer for the verification
// material of every claim held locally, not of the claims that arrived in the last sync batch.
//
// That distinction is the whole design (#62). Material is attached out of band and AFTER a record
// exists - a claim mirrored at seq 5 may be given its Sigstore bundle a week later, when the peer's
// cursor is long past it. Carrying material inside the /sync response would therefore look like it
// worked, deliver the current batch's evidence, and silently miss every later attachment: the shape
// of a mirror that reports success while omitting things.
//
// So this is O(N) requests and may be slow. Slowness is honest; there is no batch for it to walk
// past. When material gains a durable cursor of its own this becomes an incremental pass and the
// flag keeps its meaning.
func pullMaterial(dir, peer string) error {
	r, err := nreg.Open(dir)
	if err != nil {
		return err
	}
	ids := r.ClaimIDs()
	added, asked, failed := 0, 0, 0
	for _, id := range ids {
		asked++
		resp, err := http.Get(fmt.Sprintf("%s/material?subject=%s", peer, url.QueryEscape(id)))
		if err != nil {
			failed++
			continue
		}
		var body struct {
			Material []nreg.VerificationMaterial `json:"material"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if derr != nil {
			failed++
			continue
		}
		have := map[string]bool{}
		for _, m := range r.Material(id) {
			have[m.Scheme+"\x00"+m.Material] = true
		}
		for _, m := range body.Material {
			// Idempotent by (scheme, bytes): a second pass must not double every bundle. Material is
			// evidence, so duplicates are harmless to correctness and corrosive to a file.
			if have[m.Scheme+"\x00"+m.Material] {
				continue
			}
			m.Subject = id // never trust the peer's subject field over the record we asked about
			if err := r.AttachMaterial(m); err != nil {
				failed++
				continue
			}
			added++
		}
	}
	fmt.Printf("material: asked %d claim(s), stored %d new\n", asked, added)
	if failed > 0 {
		// Not an error: material is evidence ABOUT records and its absence changes nothing about
		// them (§8.1). But a silent partial answer is what this project keeps finding, so say it.
		fmt.Fprintf(os.Stderr, "note: %d request(s) or attachment(s) failed - this copy of the evidence is INCOMPLETE; re-run to complete it\n", failed)
	}
	fmt.Fprintln(os.Stderr, "note: stored, NOT verified - the kernel evaluates no verification material (SPEC §8.1)")
	return nil
}
