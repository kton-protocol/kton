// Command plankton is the Phase 0 reference CLI for the plankton kernel:
// verify DSSE attestations, ingest fotons, and query the metadata graph by hash.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

const usage = `plankton - content-addressed lineage substrate (reference)

usage:
  plankton keygen <name>                              generate a signing identity (<name>.key/.pub)
      --seed <64-hex>                                 derive it from a seed, not the entropy pool, so a corpus or
                                                      snapshot rebuilds to the same record ids (fixtures only:
                                                      the key is only as strong as its seed)
  plankton pubkey <key.key|hex>                       print the public key hex (what verify/--trust-keys read)
  plankton keyid <key.pub|key.key|hex>                print the keyid shown in signatures (map key -> identity)
  plankton author --in F ... --out F ... --cmd "…" [--located PATH=URL] [--sign key.key] [-o out] [--add]
        author + sign a foton over EXISTING files (hashes them + RECORDS --cmd as a label; never runs it).
        --in EVERY input, INCLUDING the script/code that produced the output — not just the data files.
        --located PATH=URL records where a file's bytes live (file:///abs, https://…) for any --in/--out path,
          so a viewer can fetch + re-hash it. CARRIED: it does NOT change the foton id (add locators freely).
          --located-auto defaults a file://<abs> locator for every --in/--out (skip the per-path repetition).
        --print-id prints ONLY the bare foton id on stdout (human lines to stderr): ID=$(plankton author … --print-id).
        The foton id is the hash of the DESCRIPTOR (in/out names+hashes + --cmd), NOT the signature — so a
          byte-identical descriptor yields the SAME foton id: a second producer of an identical run is the SAME
          foton, and its signature is UNIONED onto the record (both signers survive, order-independent). Count
          independent producers with 'plankton reproductions --trust-keys' (verified), or attest a reproduction
          with a nekton 'reproduces' claim — do NOT tweak --cmd to force a new id.
        --add ingests it directly (one step, no file); --registry D picks the store.
  plankton author <spec.json> <key.hex> <out.dsse>    author + sign a foton from a spec file
  plankton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>  verify a DSSE signature (envelope FILE or a
                                                      registry id; pubkey: a .pub file or the hex)
  plankton add <envelope.dsse.json> [--registry D]    ingest a signed foton into the registry (D or PLANKTON_DIR)
  plankton show <foton.dsse.json|sha256:id> [--json]  print a foton: command, environment, inputs, outputs
      --json on show/producer/uses/lineage/reproductions: the machine form. A record's id is a
      NAMED field there, so a consumer never has to assume it is the first hash on a line.
  plankton producer [--source D] [--json] <sha256:…>  who produced this file (who OUTPUT it; lineage join)
  plankton reproductions [--trust-keys D] [--json] <sha256:h>  ↻N: distinct VERIFIED independent signers that produced these
                                                      bytes. WITHOUT --trust-keys the count is self-declared and
                                                      FORGEABLE (a relabeled keyid inflates it); over PLANKTON_DIR
                                                      only - the federated ↻N is the aggregator's.
  plankton uses [--source D] [--json] <sha256:…>      what CONSUMED this file (downstream; the shared-input join)
  plankton reuse <foton.statement.json>               action key + cache-hit check
  plankton lineage [--source D] [--json] <sha256:…>   walk producers backwards (union of --source registries, no copy;
                                                      a missing --source is an error, not a silently-dropped source)
        [--sources-file F] a newline-delimited list of sources (escapes ARG_MAX; empty list is an error, not a fallback);
        [--strict] refuse (exit non-zero) if the read is incomplete (any record skipped) OR any record is unsigned;
                   --strict is COMPLETENESS + signature-PRESENCE, not authenticity - use 'plankton verify' for that
  plankton reproduces <ref-out-hash> <cand-out-hash> [--via <potential>]
                                                      do two OUTPUTS reproduce? args are OUTPUT content hashes
                                                      ('plankton hash out.csv'), NOT foton ids. --via normalises
                                                      before compare. exit 0 = L0/L1 match, 1 = none
  plankton spectrum define --id <id> [--member n=sha256:..] [--normaliser P] [-o file|-]
                                                      writes the spectrum to <id>.spectrum.json (or stdout with -o - ;
                                                      the status line goes to stderr, so a > redirect never eats it)
  plankton spectrum show  <spectrum.json>             a spectrum defines a TOOL: its reference fotons
  plankton spectrum check <spectrum.json> --candidate n=sha256:..
                                                      is the spectrum FULFILLED? (reproducible compare, runs nothing).
                                                      exit 0 = all fulfilled, 1 = a candidate FAILED, 2 = INCOMPLETE
                                                      (a member had no candidate). the L0/L1 judgment is a nekton claim on top
  plankton export [--title T] [out]                   serialize the horizon graph as JSON (headless query)
  plankton export --rdf [--lineage <id|hash>] [-o o]  project lineage as RDF/Turtle (PROV; joins nekton RDF)
  plankton hash <file>                                content address a file
  plankton mirror <local-registry-dir>                overlay a peer registry by hash (local, no network)
  plankton man                                        print the embedded manual page (roff)

federation over the NETWORK (serving a port, mirroring a URL peer), transparency-log
anchoring, and byte pinning are NOT kernel operations - the kernel opens no ports and needs
no network. They live in the cockpit: see 'kton serve', 'kton mirror', 'kton anchor',
'kton pin', 'kton blob'. Local overlay-by-hash (above) stays here: it is pure federation.

env:
  PLANKTON_DIR   registry directory (default ./plankton-data)
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

func dir() string {
	if d := os.Getenv("PLANKTON_DIR"); d != "" {
		return d
	}
	return "./plankton-data"
}

// readEnvelopeOrID accepts a bare/stored envelope FILE, or a "sha256:<id>" that it resolves from the
// registry object store (so `verify sha256:<id>` works without reaching into objects/sha256/ by hand -
// cold-session finding: verify needed a file path, forcing manual layout knowledge).
func readEnvelopeOrID(arg string) (core.Envelope, error) {
	if strings.HasPrefix(arg, "sha256:") {
		p := filepath.Join(dir(), "objects", "sha256", strings.TrimPrefix(arg, "sha256:")+".json")
		env, err := readEnvelope(p)
		if err != nil {
			return core.Envelope{}, fmt.Errorf("no record %s in the registry (%s)", arg, dir())
		}
		return env, nil
	}
	return readEnvelope(arg)
}

func readEnvelope(path string) (core.Envelope, error) {
	var env core.Envelope
	b, err := os.ReadFile(path)
	if err != nil {
		return env, err
	}
	// Accept a bare DSSE envelope OR a stored registry object {fotonId|claimId, envelope}. The
	// format `add` persists into the registry (objects/sha256/*.json) is the wrapper, not the bare
	// envelope; verifying a stored object should just work, not look like a tamper (round-4 +
	// federation finding, hit repeatedly).
	var wrap struct {
		Envelope *core.Envelope `json:"envelope"`
	}
	if json.Unmarshal(b, &wrap) == nil && wrap.Envelope != nil && wrap.Envelope.Payload != "" {
		return *wrap.Envelope, nil
	}
	return env, json.Unmarshal(b, &env)
}

// loadPubArg accepts a public key as EITHER a path to a .pub file OR the hex string itself.
// (Cycle-1 finding: the "<pubkey.hex>" placeholder led users to paste `$(cat key.pub)`, which
// was then read as a filename.) If the argument names a readable file, its contents are used;
// otherwise the argument is treated as the hex directly.
func loadPubArg(s string) (ed25519.PublicKey, error) {
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	return core.ParsePublicKeyHex(strings.TrimSpace(txt))
}

// loadTrustKeys reads every *.pub (raw hex Ed25519) under dir into a slice of public keys - the
// verifier's trusted key set. Attribution in an export is derived by checking which of THESE keys
// actually signed a record (core.VerifiedSignerKeyID), never the record's self-declared keyid, so a
// relabelled attribution is dropped rather than presented as established.
func loadTrustKeys(dir string) ([]ed25519.PublicKey, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		pub, err := core.ParsePublicKeyHex(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("trust-keys: %s: %w", e.Name(), err)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

// readSourcesFile reads a newline-delimited list of --source registry directories (blank lines and
// #comments ignored), so a large federation is not capped by ARG_MAX on repeating --source.
func readSourcesFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out, nil
}

func run(cmd string, args []string) error {
	switch cmd { // help/version in COMMAND position (not just as a flag) should not be "unknown command"
	case "--help", "-h", "help":
		fmt.Print(usage)
		return nil
	case "--version", "-v", "version":
		fmt.Println("plankton 0.2 (reference)")
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
	case "keygen":
		return keygen(args)

	case "pubkey":
		// Recover the .pub hex from a private key. Needed because an identity can be written by hand
		// (a bare 32-byte seed is a valid .key), and verify / --trust-keys / the viewer key dirs all
		// read the public half.
		if len(args) != 1 {
			return fmt.Errorf("usage: plankton pubkey <key.key|hex>")
		}
		return pubkey(args[0])

	case "keyid":
		// Map a key file/hex to the short keyid shown as `by=key:<id>` / in signatures - so you can tell
		// WHICH identity signed a record (cold-session finding: no way to resolve key: back to a session).
		if len(args) != 1 {
			return fmt.Errorf("usage: plankton keyid <key.pub|key.key|hex>  (prints the keyid shown in signatures)")
		}
		id, err := keyidOf(args[0])
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil

	case "reproductions":
		// Headless ↻N: how many INDEPENDENT signers produced this exact output? A signer counts only if
		// its signature VERIFIES against a trusted key (--trust-keys). The self-declared keyid is NOT in
		// the DSSE PAE, so counting it is FORGEABLE - a relabeled keyid inflates ↻N and mis-attributes a
		// reproduction to a party who never signed (red-team round 10, RED-1). Without --trust-keys the
		// count is self-declared and is loudly flagged as such. (Reproduces CLAIMS are an additional
		// nekton attestation layer - `nekton about <producer-foton>`.)
		var trusted []ed25519.PublicKey
		var rest []string
		asJSON := false
		for i := 0; i < len(args); i++ {
			if args[i] == "--json" {
				asJSON = true
			} else if args[i] == "--trust-keys" {
				if i+1 >= len(args) {
					return fmt.Errorf("--trust-keys expects a directory of *.pub keys")
				}
				i++
				ks, err := loadTrustKeys(args[i])
				if err != nil {
					return err
				}
				trusted = ks
			} else {
				rest = append(rest, args[i])
			}
		}
		if len(rest) != 1 {
			return fmt.Errorf("usage: plankton reproductions [--trust-keys <dir>] [--json] <sha256:output-hash>\n" +
				"  distinct INDEPENDENT producers of these bytes. With --trust-keys only signers whose signature\n" +
				"  VERIFIES are counted (the trustworthy ↻N); without it the count is self-declared and forgeable.\n" +
				"  Counted over PLANKTON_DIR only; the federated ↻N is the aggregator's.")
		}
		h := rest[0]
		if n, ok := core.NormalizeContentHash(h); ok {
			h = n
		}
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		prods := r.Producer(h)
		if len(prods) == 0 {
			// Still emit a parseable answer before the non-zero exit: a consumer must be able to read
			// "zero producers" as a RESULT, not have to infer it from an exit code and empty stdout.
			if asJSON {
				_ = printJSON(map[string]any{"output": h, "distinctSigners": 0, "producerFotons": 0, "producers": []any{}})
			} else {
				fmt.Printf("reproductions: 0 - no foton in %s produced %s\n", dir(), h)
			}
			os.Exit(1)
		}
		type prodInfo struct {
			id, signer string
			verified   bool
		}
		var infos []prodInfo
		signers := map[string]bool{}
		excluded := 0
		for _, id := range prods {
			env, ok := r.Envelope(id)
			if !ok || len(env.Signatures) == 0 {
				continue
			}
			if len(trusted) > 0 {
				// count EVERY trusted key that actually signed this envelope (a merged twin can carry
				// several co-signatures over one payload), never the self-declared keyid.
				matched := false
				for _, pub := range trusted {
					if okv, verr := env.Verify(pub); okv && verr == nil {
						kid := core.KeyIDHex(pub)
						infos = append(infos, prodInfo{id, kid, true})
						signers[kid] = true
						matched = true
					}
				}
				if !matched {
					excluded++ // signed by no trusted key -> does not count toward ↻N
				}
			} else {
				kid := env.Signatures[0].KeyID // self-declared, UNVERIFIED
				infos = append(infos, prodInfo{id, kid, false})
				signers[kid] = true
			}
		}
		kind := "self-declared"
		if len(trusted) > 0 {
			kind = "verified"
		}
		if asJSON {
			ps := make([]map[string]any, 0, len(infos))
			for _, in := range infos {
				// `verified` per record rather than one word for the whole answer: without --trust-keys
				// the count is forgeable, and a machine reader must see that on the record it acts on,
				// not only in a stderr warning it may never read.
				ps = append(ps, map[string]any{"fotonId": in.id, "keyid": in.signer, "verified": in.verified})
			}
			out := map[string]any{
				"output": h, "distinctSigners": len(signers), "producerFotons": len(prods),
				"trust": kind, "producers": ps,
			}
			if excluded > 0 {
				out["excludedUntrusted"] = excluded
			}
			if err := printJSON(out); err != nil {
				return err
			}
		} else {
			fmt.Printf("reproductions: %d distinct %s signer(s) produced %s  (↻%d; %d producer foton(s))\n",
				len(signers), kind, h, len(signers), len(prods))
			for _, in := range infos {
				fmt.Printf("  %s  by key:%s (%s)\n", in.id, in.signer, kind)
			}
		}
		if len(trusted) == 0 {
			fmt.Fprintln(os.Stderr, "warning: this ↻N is over SELF-DECLARED keyids and is FORGEABLE (a relabeled keyid inflates it and mis-attributes); pass --trust-keys <dir> to count only authenticated signers")
		} else if excluded > 0 {
			fmt.Fprintf(os.Stderr, "note: %d producer foton(s) were signed by no trusted key and were EXCLUDED from ↻N\n", excluded)
		}
		return nil

	case "author":
		// Two forms: the flag form (--in/--out/--cmd, hashes existing files for you) and the
		// original spec-file form (<spec.json> <key.hex> <out.dsse.json>). Neither runs anything.
		if len(args) > 0 && strings.HasPrefix(args[0], "-") {
			return authorConvenience(args)
		}
		if len(args) != 3 {
			return fmt.Errorf("usage: plankton author --in F --out F --cmd \"…\" [--sign key.key] [-o out] [--add] [--registry <dir>]\n" +
				"   or: plankton author <spec.json> <key.hex> <out.dsse.json>")
		}
		return author(args[0], args[1], args[2])

	case "export":
		// plankton export [--title T] [out] - serialize the horizon graph as JSON. A headless
		// query projection (spec F5.3, N1); RENDERING (HTML, audio, UI) is a cockpit's job, not
		// the kernel's (charter: the substrate stores and connects, it does not render).
		//   plankton export --rdf [--lineage <fotonId|outputHash>] [-o out]
		// projects the lineage as RDF/Turtle (PROV-O), reusing the nekton nanopub IRIs so the two
		// graphs merge for cross-layer reasoning. --lineage restricts output to one record's subset.
		if len(args) > 0 && args[0] == "--rdf" {
			sel, out := "", "-"
			var trustKeys []ed25519.PublicKey
			for i := 1; i < len(args); i++ {
				switch args[i] {
				case "--lineage":
					if i+1 >= len(args) {
						return fmt.Errorf("--lineage expects a foton id or output hash")
					}
					i++
					sel = args[i]
				case "-o":
					if i+1 >= len(args) {
						return fmt.Errorf("-o expects a path")
					}
					i++
					out = args[i]
				case "--trust-keys":
					// The verifier's trusted public keys (a dir of *.pub). Attribution is then derived from
					// which of THESE keys actually signed each foton, not the self-declared keyid.
					if i+1 >= len(args) {
						return fmt.Errorf("--trust-keys expects a directory of *.pub keys")
					}
					i++
					ks, err := loadTrustKeys(args[i])
					if err != nil {
						return err
					}
					trustKeys = ks
				default:
					return fmt.Errorf("usage: plankton export --rdf [--lineage <fotonId|outputHash>] [--trust-keys <dir>] [-o out]")
				}
			}
			return exportRDF(dir(), sel, out, trustKeys)
		}
		title, out := "plankton horizon", "-"
		for i := 0; i < len(args); i++ {
			if args[i] == "--title" && i+1 < len(args) {
				i++
				title = args[i]
			} else if strings.HasPrefix(args[i], "-") {
				// Reject an unknown flag instead of routing it (and its value) into [out]:
				// `plankton export --source x.json` used to treat x.json as the output path and
				// silently OVERWRITE it (data loss). Fail loudly.
				return fmt.Errorf("unknown flag %q for export (usage: plankton export [--title T] [out]; RDF form: export --rdf [--lineage id] [-o out])", args[i])
			} else {
				out = args[i]
			}
		}
		return exportJSON(dir(), title, out)

	case "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: plankton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>")
		}
		env, err := readEnvelopeOrID(args[0])
		if err != nil {
			return err
		}
		pub, err := loadPubArg(args[1])
		if err != nil {
			return err
		}
		if st, serr := env.Statement(); serr == nil {
			fmt.Printf("predicateType:   %s\n", st.PredicateType)
		}
		signerKeyid := ""
		if len(env.Signatures) > 0 {
			signerKeyid = env.Signatures[0].KeyID
		}
		suppliedKeyid := keyidHex(pub)
		fmt.Printf("declared keyid:  %s (unauthenticated envelope field)\n", signerKeyid)
		fmt.Printf("your key keyid:  %s\n", suppliedKeyid)
		ok, verr := env.Verify(pub)
		switch {
		case verr != nil:
			// a corrupt envelope (bad base64, no signature) is not verifiable at all.
			fmt.Println("signature:       INVALID - envelope is corrupt / not a valid DSSE")
			os.Exit(1)
		case ok:
			fmt.Printf("signature:       VALID - verified as keyid %s (the authoritative signer)\n", suppliedKeyid)
			if suppliedKeyid != signerKeyid {
				fmt.Printf("                 NOTE: the envelope declares keyid %s, which differs from the verifying key; the declared field is unauthenticated and must not be trusted.\n", signerKeyid)
			}
			return nil
		case suppliedKeyid != signerKeyid:
			// The supplied key is simply not the signer's key. This is a KEY MISMATCH, not evidence
			// of tampering - you verified against the wrong identity. Fetch the signer's actual key.
			fmt.Println("signature:       UNVERIFIED - WRONG KEY: this key did not sign the record")
			fmt.Printf("                 (the envelope declares keyid %s - an unauthenticated hint; obtain and verify against the real signer's key)\n", signerKeyid)
			os.Exit(2)
		default:
			// keyid matches the signer, yet the signature does not verify → the bytes were ALTERED
			// after signing. This is a genuine integrity failure, distinct from a wrong-key mismatch.
			fmt.Printf("signature:       INVALID - TAMPERED: content does not match the signature for keyid %s\n", signerKeyid)
			os.Exit(1)
		}
		return nil

	case "add":
		// Accepts MORE THAN ONE path on purpose: registry.Open replays the whole log to rebuild its
		// indexes, so a shell loop over N files costs N replays - quadratic, and measurably unusable
		// on a real corpus (2.2 s per record at 1k already stored). Bulk arrival is the normal case
		// for this substrate, not an edge case: federation hands you a set, an executor publishes a
		// batch of runs, a consumer imports a corpus someone handed over. Open once, then ingest.
		regDir := ""
		var paths []string
		for i := 0; i < len(args); i++ {
			if args[i] == "--registry" && i+1 < len(args) {
				i++
				regDir = args[i]
			} else {
				paths = append(paths, args[i])
			}
		}
		if len(paths) == 0 {
			return fmt.Errorf("usage: plankton add <envelope.dsse.json>... [--registry <dir>]")
		}
		r, err := registry.Open(regOrDefault(regDir))
		if err != nil {
			return err
		}
		if len(paths) > 1 {
			// A record rejected ON ITS MERITS does not wedge the import: it is named, counted, and
			// the rest still lands - the same call federation's Mirror already makes. A LOCAL
			// persistence failure is different (transient, and skipping it would silently drop a
			// valid record), so that aborts. Either way the exit is non-zero when anything was
			// refused: a partial import that reports success is how a corpus quietly loses records.
			added, present := 0, 0
			var refused []string
			for _, p := range paths {
				env, err := readEnvelope(p)
				if err != nil {
					refused = append(refused, fmt.Sprintf("%s: %v", p, err))
					continue
				}
				_, isNew, err := r.Add(env)
				if err != nil {
					if errors.Is(err, registry.ErrPersist) {
						return fmt.Errorf("%s: %w", p, err)
					}
					refused = append(refused, fmt.Sprintf("%s: %v", p, err))
					continue
				}
				if isNew {
					added++
				} else {
					present++
				}
			}
			for _, m := range refused {
				fmt.Fprintln(os.Stderr, "refused: "+m)
			}
			fmt.Printf("indexed %d fotons, %d already present, %d refused  (registry now holds %d)\n",
				added, present, len(refused), r.Len())
			if len(refused) > 0 {
				return fmt.Errorf("%d of %d record(s) refused", len(refused), len(paths))
			}
			return nil
		}
		env, err := readEnvelope(paths[0])
		if err != nil {
			return err
		}
		id, isNew, err := r.Add(env)
		if err != nil {
			return err
		}
		if !isNew {
			fmt.Printf("already present: foton %s\n", id)
		} else {
			fmt.Printf("indexed foton %s  (registry now holds %d fotons)\n", id, r.Len())
		}
		// add RECORDS; it does not judge trust. A signature is only checked when you ask
		// (`plankton verify`) - so an unverified or tampered record ingests here without complaint.
		// Say so, so the gap is never silent.
		fmt.Fprintln(os.Stderr, "note: recorded without verifying - run `plankton verify <envelope> <signer-pubkey>` to check authenticity")
		return nil

	case "reproduces":
		// plankton reproduces <refHash> <candHash> [--via <normalizer potential>]
		// Reproduction-identity by hash alone: L0 (raw outputs equal) or L1 (equal after the SAME
		// normalizer potential - its protocol ref, or a normalizer foton id). L2 (tolerance) is a
		// comparator's signed verdict, not a kernel check. --via names a POTENTIAL, not a kind: two
		// different normalizers of the same kind are different comparisons (SPEC §9).
		var ref, cand, via string
		for i := 0; i < len(args); i++ {
			if args[i] == "--via" && i+1 < len(args) {
				i++
				via = args[i]
			} else if ref == "" {
				ref = args[i]
			} else {
				cand = args[i]
			}
		}
		if ref == "" || cand == "" {
			return fmt.Errorf("usage: plankton reproduces <ref-output-hash> <cand-output-hash> [--via <normalizer: protocol ref or foton id>]\n" +
				"  args are OUTPUT content hashes (e.g. `plankton hash out.csv`), NOT foton ids")
		}
		// Normalize the output-hash args to canonical lowercase (SPEC §5.1) so a bare/uppercase hash
		// resolves; --via may be a ref or foton id, so normalize it only if it is a content hash.
		if n, ok := core.NormalizeContentHash(ref); ok {
			ref = n
		}
		if n, ok := core.NormalizeContentHash(cand); ok {
			cand = n
		}
		if n, ok := core.NormalizeContentHash(via); ok {
			via = n
		}
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		level := ""
		identical := false
		if ref == cand {
			level = "L0"
			identical = true // L0 by definition means identical output bytes -> identical hash.
		} else if via != "" {
			if nr := r.NormalizedOutput(ref, via); nr != "" && nr == r.NormalizedOutput(cand, via) {
				level = "L1"
			}
		}
		if level == "" {
			fmt.Println("reproduction: none (no L0/L1 match - an L2 comparator verdict is required)")
			os.Exit(1)
		}
		if identical {
			// The expected PASS: two independent runs producing the same bytes hash to the same value, so
			// the args are equal - that is success, not a mistake. Independence is carried by the two
			// SEPARATE producer fotons + the reproduces claim, not by this byte compare.
			fmt.Printf("reproduction: %s - identical output bytes (expected for L0). Independence is attested by the\n"+
				"separate producer fotons + your reproduces claim, not by this byte compare.\n", level)
		} else {
			fmt.Printf("reproduction: %s\n", level)
			if level == "L1" && via != "" {
				// SPEC §9: an L1 result is only as trustworthy as the normalizer behind it. The kernel
				// renders the mechanical match; establishing that the normalizer is itself L0-qualified
				// (byte-exact re-run) is a CONSUMER obligation - surface it rather than trust it silently.
				fmt.Fprintf(os.Stderr, "note: this L1 holds only if the normalizer %q is itself L0-qualified (a byte-exact re-run) - a §9 consumer obligation; qualify it first with `plankton reproductions --trust-keys <dir> <normalizer-output>` (↻>=2) or a spectrum before trusting this result\n", via)
			}
		}
		return nil

	case "producer", "uses", "lineage":
		// Multi-source read (SPEC Clause 11): resolve over the UNION of the named sources at query
		// time, no copy. Repeat --source to add registries; without any, the single PLANKTON_DIR is
		// used. Records are content-addressed, so the union is deduped and conflict-free.
		var sources []string
		q := ""
		strict := false
		asJSON := false
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "--json":
				asJSON = true
			case args[i] == "--source" && i+1 < len(args):
				i++
				sources = append(sources, args[i])
			case args[i] == "--sources-file" && i+1 < len(args):
				// A newline-delimited list of source dirs - escapes the ARG_MAX cap on repeating
				// --source for a large federation (blank lines and #comments ignored).
				i++
				more, ferr := readSourcesFile(args[i])
				if ferr != nil {
					return ferr
				}
				if len(more) == 0 {
					// A sources-file that resolves to NO sources must not silently fall back to the
					// default PLANKTON_DIR: the caller explicitly scoped the read to that (empty) set,
					// and answering over their own default registry instead is a wrong, unflagged answer.
					return fmt.Errorf("--sources-file %q lists no sources (blank or all-comments); refusing to fall back to the default registry", args[i])
				}
				sources = append(sources, more...)
			case args[i] == "--strict":
				strict = true
			case strings.HasPrefix(args[i], "--"):
				return fmt.Errorf("unknown flag %q", args[i])
			default:
				q = args[i]
			}
		}
		if q == "" {
			return fmt.Errorf("usage: plankton %s [--source D ...] [--sources-file F] [--strict] [--json] <sha256:...>", cmd)
		}
		var r *registry.Registry
		var err error
		if len(sources) > 0 {
			r, err = registry.OpenUnion(sources...)
		} else {
			r, err = registry.Open(dir())
		}
		if err != nil {
			return err
		}
		// A degraded read (records skipped as corrupt/planted) is INCOMPLETE - surface it, and with
		// --strict refuse to answer, so a scripted gate/CI never trusts a partial provenance answer.
		if n := r.Degraded(); n > 0 {
			fmt.Fprintf(os.Stderr, "warning: %d record(s) skipped on load - this read is INCOMPLETE\n", n)
			if strict {
				return fmt.Errorf("--strict: refusing to answer over an incomplete read (%d record(s) skipped)", n)
			}
		}
		// --strict also refuses over records that carry no well-formed signature. Add rejects unsigned
		// records at ingest (SPEC §8), but the read path indexes whatever is on disk, so a record planted
		// directly into objects/ can slip in unsigned. This is a KEYLESS structural guard (absent/corrupt
		// signature), NOT cryptographic verification - a strict answer is COMPLETE and SIGNED, but proving
		// WHO signed still needs `plankton verify` with the signer's key.
		if strict {
			if n := r.Unsigned(); n > 0 {
				return fmt.Errorf("--strict: refusing to answer - %d record(s) lack a well-formed signature (use `plankton verify` to check authenticity)", n)
			}
		}
		// Normalize the query hash to canonical lowercase (SPEC §5.1): a bare 64-hex or an uppercase
		// digest resolves under the same key the index was built with (FileRef hashes are stored
		// "sha256:<lowerhex>"). Without this, `plankton uses <barehex>` misses and misreads as a root.
		if norm, ok := core.NormalizeContentHash(q); ok {
			q = norm
		}
		var ids []string
		switch cmd {
		case "producer":
			ids = r.Producer(q)
		case "uses":
			ids = r.Uses(q)
		case "lineage":
			ids = r.Lineage(q)
		}
		// --json exists to REPLACE line scraping, not to pretty-print it. A consumer that regexes
		// ids out of the prose above has to assume a record's own id is the first hash on its line;
		// that holds today, is guaranteed nowhere, and no test protects it (#57). Here the id is a
		// named field, so a reordered output line cannot silently mislabel a record.
		if asJSON {
			recs := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				f, _ := r.Foton(id)
				recs = append(recs, map[string]any{
					"fotonId": id, "kind": f.Protocol.Kind,
					"inputs": len(f.Inputs), "outputs": len(f.Outputs),
				})
			}
			out := map[string]any{"relation": cmd, "query": q, "records": recs}
			if len(sources) > 0 {
				out["sources"] = sources
			}
			// A degraded read is INCOMPLETE, and that must survive into the machine form - a consumer
			// that cannot see it would treat a partial provenance answer as a whole one.
			if n := r.Degraded(); n > 0 {
				out["incomplete"] = true
				out["skippedRecords"] = n
			}
			return printJSON(out)
		}
		if len(ids) == 0 {
			where := "this registry"
			if len(sources) > 0 {
				where = fmt.Sprintf("the %d named source(s)", len(sources))
			}
			fmt.Printf("(none) - %s is a lineage root or unknown in %s\n", q, where)
			return nil
		}
		for _, id := range ids {
			f, _ := r.Foton(id)
			fmt.Printf("%s  kind=%s  in=%d out=%d\n", id, f.Protocol.Kind, len(f.Inputs), len(f.Outputs))
		}
		return nil

	case "reuse":
		if len(args) != 1 {
			return fmt.Errorf("usage: plankton reuse <foton.statement.json>")
		}
		b, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		// Accept a DSSE envelope (what a cockpit holds) or a bare statement.
		var st core.Statement
		var env core.Envelope
		if json.Unmarshal(b, &env); env.Payload != "" {
			pb, perr := env.PayloadBytes()
			if perr != nil {
				return perr
			}
			if err := json.Unmarshal(pb, &st); err != nil {
				return err
			}
		} else if err := json.Unmarshal(b, &st); err != nil {
			return err
		}
		f, err := st.ToFoton()
		if err != nil {
			return err
		}
		// A foton whose wire ref disagrees with its descriptor is malformed (SPEC §6.2); reject it
		// rather than compute a cache key from a lie (cold-session cache-poisoning finding). The
		// action key itself now derives the ref from the descriptor, so a HIT reflects the real
		// protocol even for a bare (descriptor-less) reference.
		if err := f.CheckProtocolRef(); err != nil {
			return err
		}
		ak, err := f.ActionKey()
		if err != nil {
			return err
		}
		fmt.Printf("action key: %s\n", ak)
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		hits := r.Reuse(ak)
		if len(hits) == 0 {
			fmt.Println("cache: MISS (no prior computation with these inputs+protocol)")
		} else {
			// A cache key binds inputs+protocol, NOT outputs or signer (it can't - you look up BY inputs
			// to FIND the outputs, and binding the signer would break cross-party reuse). So an action
			// key can have SEVERAL hits by DIFFERENT signers with DIFFERENT outputs - anyone may author a
			// foton with these inputs. List each hit's declared signer + output so a COMPETING/injected
			// result is visible, and the consumer picks a signer it trusts and verifies (not a bare HIT).
			fmt.Printf("cache: HIT -> %d prior computation(s) with these inputs+protocol:\n", len(hits))
			for _, id := range hits {
				signer := "(unsigned)"
				if env, ok := r.Envelope(id); ok && len(env.Signatures) > 0 && env.Signatures[0].KeyID != "" {
					signer = env.Signatures[0].KeyID
				}
				var outs []string
				if f, ok := r.Foton(id); ok {
					for _, o := range f.Outputs {
						outs = append(outs, o.Hash)
					}
				}
				fmt.Printf("  %s  declared-signer=%s (unverified)  output=%s\n", id, signer, strings.Join(outs, ", "))
			}
			fmt.Fprintln(os.Stderr, "note: these are COMPETING cache-key matches, not a trusted result - anyone can author a foton with these inputs, and their OUTPUTS may differ. Pick a hit whose SIGNER you trust and `plankton verify` it.")
		}
		return nil

	case "hash":
		if len(args) != 1 {
			return fmt.Errorf("usage: plankton hash <file>")
		}
		b, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		fmt.Println(core.HashBytes(b))
		return nil

	case "show":
		return show(args)

	case "spectrum":
		return spectrum(args)

	case "mirror":
		// Pure federation: overlay a peer registry that lives on the local filesystem by hash.
		// No net/http - reading a peer's append-only log and re-adding its signed fotons is a
		// data operation, so it stays in the kernel. Network peers (URLs) are a cockpit concern.
		if len(args) != 1 {
			return fmt.Errorf("usage: plankton mirror <local-registry-dir>")
		}
		peer := args[0]
		if strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
			return fmt.Errorf("network peer %s - use: kton mirror plankton %s", peer, peer)
		}
		if fi, err := os.Stat(peer); err != nil || !fi.IsDir() {
			return fmt.Errorf("peer registry %q does not exist (nothing to mirror)", peer)
		}
		local, err := registry.Open(dir())
		if err != nil {
			return err
		}
		src, err := registry.Open(peer)
		if err != nil {
			return fmt.Errorf("open peer %s: %w", peer, err)
		}
		added := 0
		for _, rec := range src.Records(0) {
			if _, isNew, err := local.Add(rec.Envelope); err == nil && isNew {
				added++
			}
		}
		fmt.Printf("mirrored %s: %d new; registry holds %d fotons\n", peer, added, local.Len())
		return nil

	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func boolWord(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
