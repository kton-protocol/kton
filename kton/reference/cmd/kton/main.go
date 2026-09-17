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
	"errors"
	"fmt"
	"os"
	"strings"

	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
	preg "kton.dev/plankton/registry"

	nreg "kton.dev/nekton/registry"
)

const usage = `kton - the cockpit that conducts plankton + nekton (reimplements nothing)

usage:
  kton mirror plankton <dir>               pull+persist a peer plankton registry
  kton mirror nekton   <dir>               pull+persist a peer nekton registry
  kton anchor <envelope.dsse.json> <pubkey.pub|hex> [--store]
                                           anchor a signed record in the Rekor transparency log
      --store            record the verified entry as §8.1 verification material ON the record,
                         which is what §13 asks for - otherwise the proof is only printed, and a
                         year from now verification depends on the service still answering
  kton pin    <file>                       DEPRECATED - use 'plankton pin'
  kton blob   <sha256:...>                 DEPRECATED - use 'plankton blob'
      both moved to the kernel: pinning needs no address, only a hash, so it is not a cockpit
      capability. They still work and reach the SAME store; they go when the cockpit leaves.
  kton fetch  <sha256:...> --trust-keys <dir> [--allow-local]
                                           resolve content via located-at claims signed by a key
                                           you named, dereference, verify sha256, and pin.
      --allow-local      also accept file:// and addresses on this host/network. A signature
                         about CONTENT cannot vouch for a path on your machine.
  kton man                                 print the embedded manual page (roff)

  <dir> is a local registry directory (e.g. ../session-1/plankton-data), read directly - no
  server, no port. Mirroring a peer over a NETWORK is a cockpit capability and lives in the
  cockpit repository: this repository holds the protocol, and the protocol is about bytes, not
  about which transport carries them (SPEC §12 - the queries are normative, the transport is not).

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

// refuseNetworkPeer rejects a peer given as a URL, and says where that capability went.
//
// It is a REFUSAL, not a branch. This repository holds the protocol, and a protocol is about bytes
// - not about which other protocol carries them somewhere. Mirroring over HTTP lived here, had no
// caller anywhere (25 uses of `kton mirror`, none with a URL), and brought four unbounded HTTP
// clients with it. SPEC §12 fixes the queries and the wire form and leaves the transport
// unspecified; `plankton records --json --since N` answers sync(since) over stdout, which is what a
// cockpit reads.
func refuseNetworkPeer(peer string) error {
	if !strings.HasPrefix(peer, "http://") && !strings.HasPrefix(peer, "https://") {
		return nil
	}
	return fmt.Errorf("%s is a network peer, and this repository carries no network transport.\n"+
		"  A peer over HTTP is a cockpit capability: point the cockpit at it, or mirror a local\n"+
		"  registry directory here. SPEC §12 leaves the transport unspecified - the queries are\n"+
		"  normative, the binding is not.", peer)
}

func run(cmd string, args []string) error {
	switch cmd { // help/version in COMMAND position (not just as a flag) should not be "unknown command"
	case "--help", "-h", "help":
		fmt.Print(usage)
		return nil
	case "--version", "-v", "version":
		fmt.Println("kton 0.2.1 (reference)")
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
		if len(args) != 2 {
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <local-registry-dir>")
		}
		which, peer := args[0], strings.TrimRight(args[1], "/")
		switch which {
		case "plankton":
			return mirrorPlankton(planktonDir(), peer)
		case "nekton":
			return mirrorNekton(nektonDir(), peer)
		default:
			return fmt.Errorf("usage: kton mirror <plankton|nekton> <local-registry-dir>")
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
		// MOVED to plankton (#102): pinning needs no address, only a hash, so it is a kernel
		// operation. Kept here until the cockpit leaves this repository (#103) so kton-examples and
		// any script does not break on the same day the command moves.
		fmt.Fprintln(os.Stderr, "note: `kton pin` moved to `plankton pin`; this spelling is deprecated and will be removed")
		if len(args) != 1 {
			return fmt.Errorf("usage: kton pin <file>")
		}
		b, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		bs, err := blobstore.OpenFor(planktonDir())
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
		fmt.Fprintln(os.Stderr, "note: `kton blob` moved to `plankton blob`; this spelling is deprecated and will be removed")
		if len(args) != 1 {
			return fmt.Errorf("usage: kton blob <sha256:...>")
		}
		h := normalizeHash(args[0]) // accept bare-hex / UPPERCASE / whitespace spellings of the same hash
		bs, err := blobstore.OpenFor(planktonDir())
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

// mirrorPlankton pulls a peer plankton registry into the local one. The peer is a directory on this
// filesystem, read directly - the zero-ceremony path the lab uses for cross-session discovery: no
// server, no port. Reading a peer's append-only log and re-adding its signed fotons is a DATA
// operation and stays here; reaching a peer across a network is a transport, and transports are a
// cockpit concern (SPEC §12 leaves the transport unspecified; §1 puts hosting out of scope).
func mirrorPlankton(localDir, peer string) error {
	local, err := preg.Open(localDir)
	if err != nil {
		return err
	}
	if err := refuseNetworkPeer(peer); err != nil {
		return err
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
	added, refused, err := settleAdd(local.Add, envs)
	if err != nil {
		return fmt.Errorf("mirror of %s FAILED: %w", peer, err)
	}
	msg := fmt.Sprintf("mirrored %s: %d new", peer, added)
	if refused > 0 {
		msg += fmt.Sprintf(", %d REFUSED as invalid", refused)
	}
	fmt.Printf("%s; registry holds %d fotons\n", msg, local.Len())
	if refused > 0 {
		return fmt.Errorf("%d peer record(s) were refused - this copy is INCOMPLETE", refused)
	}
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
	if err := refuseNetworkPeer(peer); err != nil {
		return err
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
	added, refused, err := settleAdd(local.Add, envs)
	if err != nil {
		return fmt.Errorf("mirror of %s FAILED: %w", peer, err)
	}
	msg := fmt.Sprintf("mirrored %s: %d new", peer, added)
	if refused > 0 {
		msg += fmt.Sprintf(", %d REFUSED as invalid", refused)
	}
	fmt.Printf("%s; registry holds %d claim(s)\n", msg, local.Len())
	fmt.Fprintln(os.Stderr, "note: a claim whose seed or prev is not held yet is STORED and awaits it; "+
		"`nekton head <scope>` reports a scope that does not resolve.")
	if refused > 0 {
		return fmt.Errorf("%d peer claim(s) were refused - this copy is INCOMPLETE", refused)
	}
	return nil
}

// settleAdd ingests a batch and CLASSIFIES what happened, rather than retrying it.
//
// The retry loop this replaces could not heal anything. In both kernels a claim or foton whose
// dependency is missing is PERSISTED and returns nil (unresolved is incomplete, not invalid,
// SPEC §11), so it never reached the error branch; every error that did was permanent (unparseable,
// unsigned, structurally invalid) or environmental (a local write failure). The loop therefore spun,
// then reported a write failure as "2 skipped" with exit 0.
//
// A local persistence failure is returned: nothing after it can be trusted, and a caller mirroring
// into a broken destination must not read "skipped" as "the peer sent us junk".
func settleAdd(add func(core.Envelope) (string, bool, error), envs []core.Envelope) (added, refused int, err error) {
	for _, e := range envs {
		_, isNew, aerr := add(e)
		switch {
		case aerr == nil && isNew:
			added++
		case aerr == nil:
			// already held
		case errors.Is(aerr, preg.ErrPersist), errors.Is(aerr, nreg.ErrPersist):
			return added, refused, fmt.Errorf("could not write locally after %d record(s) - the local "+
				"store is incomplete and this is not a peer problem: %w", added, aerr)
		default:
			refused++
			fmt.Fprintf(os.Stderr, "warning: peer record refused: %v\n", aerr)
		}
	}
	return added, refused, nil
}

// --- nekton federation server + HTTP mirror (moved verbatim out of the nekton kernel) --------
// SPEC §6: claims by subject/object/signer/predicate + sync/mirror. This is cockpit surface,
// not kernel - it opens a port, so it lives here.

func envsOf(recs []nreg.Record) []core.Envelope {
	out := make([]core.Envelope, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.Envelope)
	}
	return out
}
