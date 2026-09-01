// Command nekton is the Phase-0 reference CLI for the nekton kernel: the commitment layer
// that records, signs-verifies, indexes, and federates SIGNED CLAIMS about plankton objects
// (and about other claims). It reuses plankton's shared `core` for canonicalization, hashing,
// and DSSE - the one allowed nekton -> plankton dependency. It never executes or reasons.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

const usage = `nekton - signed-claim commitment substrate (reference)

usage:
  nekton keygen <name>                                generate a signing identity (<name>.key/.pub)
  nekton keyid <key.pub|key.key|hex>                  print the keyid shown as by=key:<id> (map key -> signer)
  nekton seed <scope-name> --sign key.key [--add] [--registry D]  open a (sub)nekton scope; prints its scope id
        [--by ID] [--parent <parentSeedId>] [-o out]      (scoped claims chain under it via --scope/--prev)
  nekton claim <spec.json> <key.key> [<out.dsse>] [--add] [--registry D]  author + sign a claim; --add ingests directly
  nekton annotate <subj|--foton F> --template <name> [--add] [--registry D]  author + sign a claim from a TEMPLATE
        --set k=v ... --sign key.key [--by ID] [-o out]   (aliases + auto timestamp; no jq/openssl)
  nekton templates [--show <name>]                    list templates + aliases; --show prints a template's fields
  nekton show <claim.dsse.json|sha256:id>             print a claim: subject, predicate, statement, signer
  nekton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>  verify a DSSE signature (envelope FILE or a
                                                      registry id; pubkey: a .pub file or the hex)
  nekton add <envelope.dsse.json> [--registry D]      ingest a signed claim (D or NEKTON_DIR)
  nekton about <subject>                              claims about a subject (hash "sha256:..." or uri)
  nekton by <signer|predicate|object> <value>         claims by signer keyid / predicate (template/CURIE/IRI) / object
  nekton head <scope-id>                              the tip of a scope's chain (publish/anchor it to seal history)
  nekton export [--title T] [out]                     serialize claims as JSON (for the Navigator join)
  nekton export --nanopub <claim.dsse.json> [-o out]  render a claim to its nanopublication (RDF/TriG) face
  nekton nanopublish <claim.dsse.json> [--rsa key.pem] [--creator IRI] [-o out]  RSA-sign it + mint a Trusty URI
  nekton mirror <local-registry-dir>                  overlay a peer's claims by hash (local, no network)
  nekton man                                          print the embedded manual page (roff)

env:
  NEKTON_DIR         registry directory (default ./nekton-data)
  NEKTON_TEMPLATES   template directory  (default ./templates)   - federated data, not built in
  NEKTON_ALIASES     alias file          (default ./aliases.json) - CURIE/term/template sugar

templates and aliases are federated example data, not part of the protocol:
example set at github.com/gitmick/kton-examples
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
	if d := os.Getenv("NEKTON_DIR"); d != "" {
		return d
	}
	return "./nekton-data"
}

// regOrDefault returns the explicit --registry directory if given, else dir() (NEKTON_DIR or the
// default ./nekton-data). Used by every command that can add to a registry.
func regOrDefault(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return dir()
}

// readEnvelopeOrID loads a DSSE envelope from a file path, OR - if the arg is a "sha256:" claim
// id - resolves it from the local registry, so file-taking commands also accept a stored claim id.
func readEnvelopeOrID(arg string) (core.Envelope, error) {
	if strings.HasPrefix(arg, "sha256:") {
		r, err := registry.Open(dir())
		if err != nil {
			return core.Envelope{}, err
		}
		if rec, ok := r.Claim(arg); ok {
			return rec.Envelope, nil
		}
		return core.Envelope{}, fmt.Errorf("no claim %s in the registry (%s)", arg, dir())
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
	// format `add` persists into the registry is the wrapper, not the bare envelope; verifying a
	// stored object should just work, not look like a tamper (round-4 + federation finding).
	var wrap struct {
		Envelope *core.Envelope `json:"envelope"`
	}
	if json.Unmarshal(b, &wrap) == nil && wrap.Envelope != nil && wrap.Envelope.Payload != "" {
		return *wrap.Envelope, nil
	}
	return env, json.Unmarshal(b, &env)
}

func printClaims(recs []registry.Record) {
	if len(recs) == 0 {
		fmt.Println("(none)")
		return
	}
	for _, rec := range recs {
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		p, _ := st.ParsePredicate()
		term, by := "", ""
		if p != nil {
			term, by = p.Predicate.Key(), p.By
		}
		keyid := ""
		if len(rec.Envelope.Signatures) > 0 {
			keyid = rec.Envelope.Signatures[0].KeyID
		}
		// The keyid is the envelope's SELF-DECLARED field, not a verified signer (matching `show`): label
		// it so `by`/`about` output never reads as established identity - authenticity is `nekton verify`
		// with the signer's key (cold-session verified-attribution sibling: CLI display).
		fmt.Printf("%s  predicate=%s  by=%s  declared-keyid=%s (unverified)\n", rec.ClaimID, term, by, keyid)
	}
}

// printClaimsJSON emits the records VERBATIM - {claimId, envelope}, the same shape the registry
// stores and `add` accepts. Nothing is projected, ranked or interpreted: the caller decodes the
// payload exactly as the kernel does. The prose form above answers "which records, roughly"; a
// consumer of the claim axis needs the body, because a claim's meaning IS its body - the object it
// relates to does not appear in the rendered line at all.
func printClaimsJSON(recs []registry.Record) error {
	type rec struct {
		ClaimID  string        `json:"claimId"`
		Envelope core.Envelope `json:"envelope"`
	}
	out := make([]rec, 0, len(recs))
	for _, r := range recs {
		out = append(out, rec{ClaimID: r.ClaimID, Envelope: r.Envelope})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// takeJSON pulls a --json flag out of the argument list, returning the rest.
func takeJSON(args []string) ([]string, bool) {
	rest, asJSON := make([]string, 0, len(args)), false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
			continue
		}
		rest = append(rest, a)
	}
	return rest, asJSON
}

func run(cmd string, args []string) error {
	switch cmd { // help/version in COMMAND position (not just as a flag) should not be "unknown command"
	case "--help", "-h", "help":
		fmt.Print(usage)
		return nil
	case "--version", "-v", "version":
		fmt.Println("nekton 0.2 (reference)")
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
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton keygen <name>")
		}
		return keygen(args[0])

	case "keyid":
		// Map a key file/hex to the keyid shown as `by=key:<id>` on claims, so you can tell WHICH signer
		// (which session) authored a claim (cold-session finding: no keyid -> identity lookup).
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton keyid <key.pub|key.key|hex>  (prints the keyid shown as by=key:<id>)")
		}
		id, err := keyidOf(args[0])
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil

	case "claim":
		var pos []string
		addFlag, regDir := false, ""
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--add":
				addFlag = true
			case "--registry":
				i++
				if i < len(args) {
					regDir = args[i]
				}
			default:
				pos = append(pos, args[i])
			}
		}
		// out is optional when --add is given (ingest directly, no file)
		if len(pos) < 2 || (len(pos) < 3 && !addFlag) {
			return fmt.Errorf("usage: nekton claim <spec.json> <key.key> [<out.dsse.json>] [--add] [--registry <dir>]")
		}
		out := ""
		if len(pos) >= 3 {
			out = pos[2]
		}
		return authorClaim(pos[0], pos[1], out, addFlag, regDir)

	case "seed":
		return seed(args)

	case "annotate":
		return annotate(args)

	case "templates":
		return listTemplates(args)

	case "show":
		return showClaim(args)

	case "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: nekton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>")
		}
		env, err := readEnvelopeOrID(args[0])
		if err != nil {
			return err
		}
		pub, err := loadPubArg(args[1])
		if err != nil {
			return err
		}
		ok, verr := env.Verify(pub)
		if st, payload, perr := claim.ParseEnvelope(env); perr == nil {
			fmt.Printf("claim id:        %s\n", claim.ClaimID(payload))
			fmt.Printf("predicateType:   %s\n", st.PredicateType)
			if p, e := st.ParsePredicate(); e == nil {
				fmt.Printf("predicate:       %s\n", p.Predicate.Key())
			}
		}
		signerKeyid := ""
		if len(env.Signatures) > 0 {
			signerKeyid = env.Signatures[0].KeyID
		}
		suppliedKeyid := keyidHex(pub)
		fmt.Printf("declared keyid:  %s (unauthenticated envelope field)\n", signerKeyid)
		fmt.Printf("your key keyid:  %s\n", suppliedKeyid)
		switch {
		case verr != nil:
			fmt.Println("signature:       INVALID - envelope is corrupt / not a valid DSSE")
			os.Exit(1)
		case ok:
			fmt.Printf("signature:       VALID - verified as keyid %s (the authoritative signer)\n", suppliedKeyid)
			if suppliedKeyid != signerKeyid {
				fmt.Printf("                 NOTE: the envelope declares keyid %s, which differs from the verifying key; the declared field is unauthenticated and must not be trusted.\n", signerKeyid)
			}
			return nil
		case suppliedKeyid != signerKeyid:
			fmt.Println("signature:       UNVERIFIED - WRONG KEY: this key did not sign the record")
			fmt.Printf("                 (the envelope declares keyid %s - an unauthenticated hint; obtain and verify against the real signer's key)\n", signerKeyid)
			os.Exit(2)
		default:
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
			return fmt.Errorf("usage: nekton add <envelope.dsse.json>... [--registry <dir>]")
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
					// nekton's registry draws no transient/merit line the way plankton's ErrPersist
					// does, so every failure is reported by name and the exit is non-zero - the
					// caller decides what to do, rather than the import deciding silently.
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
			fmt.Printf("indexed %d claims, %d already present, %d refused  (registry now holds %d)\n",
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
			fmt.Printf("already present: claim %s\n", id)
		} else {
			fmt.Printf("indexed claim %s  (registry now holds %d claims)\n", id, r.Len())
		}
		return nil

	case "about":
		args, asJSON := takeJSON(args)
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton about <subject> [--json]  (hash \"sha256:...\" or uri)")
		}
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		if asJSON {
			return printClaimsJSON(r.About(args[0]))
		}
		printClaims(r.About(args[0]))
		return nil

	case "by":
		args, asJSON := takeJSON(args)
		if len(args) != 2 {
			return fmt.Errorf("usage: nekton by <signer|predicate|object> <value> [--json]")
		}
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		var recs []registry.Record
		switch args[0] {
		case "signer":
			recs = r.BySigner(keyidFromArg(args[1]))
		case "predicate":
			recs = r.ByPredicate(resolvePredicateArg(args[1]))
		case "object":
			recs = r.ByObject(args[1])
		default:
			return fmt.Errorf("by <signer|predicate|object> <value>")
		}
		if asJSON {
			return printClaimsJSON(recs)
		}
		printClaims(recs)
		return nil

	case "nanopublish":
		// Re-sign a claim's nanopublication with RSA (the npx convention) and mint its Trusty URI,
		// keeping the DSSE<->RSA provenance join. The publishable, network-shaped face of a claim.
		return nanopublish(args)

	case "export":
		// `nekton export --nanopub <claim.dsse.json>` renders one claim to its nanopublication
		// interop face (TriG); otherwise the JSON horizon projection for the Navigator join.
		if len(args) > 0 && args[0] == "--nanopub" {
			return exportNanopub(args[1:])
		}
		title, out, trustDir := "nekton claims", "-", ""
		for i := 0; i < len(args); i++ {
			if args[i] == "--title" && i+1 < len(args) {
				i++
				title = args[i]
			} else if args[i] == "--trust-keys" && i+1 < len(args) {
				i++
				trustDir = args[i]
			} else if len(args[i]) > 0 && args[i][0] == '-' {
				return fmt.Errorf("usage: nekton export [--title T] [--trust-keys <dir>] [out]  (or: nekton export --nanopub <claim> [-o out])")
			} else {
				out = args[i]
			}
		}
		var trustKeys []ed25519.PublicKey
		if trustDir != "" {
			ks, err := loadTrustKeys(trustDir)
			if err != nil {
				return err
			}
			trustKeys = ks
		}
		return exportJSON(dir(), title, out, trustKeys)

	case "mirror":
		// Pure federation: overlay a peer's signed claims from a local registry directory by hash.
		// The settle loop tolerates order-free delivery - a scoped child that arrives before its
		// seed is retried across passes, so a subnekton federates intact. No net/http; network
		// peers (URLs) are a cockpit concern (kton mirror nekton).
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton mirror <local-registry-dir>")
		}
		peer := args[0]
		if strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
			return fmt.Errorf("network peer %s - use: kton mirror nekton %s", peer, peer)
		}
		if fi, err := os.Stat(peer); err != nil || !fi.IsDir() {
			return fmt.Errorf("peer registry %q does not exist (nothing to mirror)", peer)
		}
		local, err := registry.Open(dir())
		if err != nil {
			return err
		}
		src, err := registry.OpenUnion(peer) // READ the peer; never MkdirAll/mutate a source we mirror from
		if err != nil {
			return fmt.Errorf("open peer %s: %w", peer, err)
		}
		pending := src.RawRecords()
		added := 0
		for {
			progress := false
			var next []registry.Record
			for _, rec := range pending {
				_, isNew, err := local.Add(rec.Envelope)
				if err != nil {
					next = append(next, rec)
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
		msg := fmt.Sprintf("mirrored %s: %d new", peer, added)
		if len(pending) > 0 {
			ids := make([]string, 0, len(pending))
			for _, rec := range pending {
				ids = append(ids, rec.ClaimID)
			}
			msg += fmt.Sprintf(", %d unresolved (missing dependency - an incomplete chain): %s", len(pending), strings.Join(ids, ", "))
		}
		fmt.Printf("%s; registry holds %d claim(s)\n", msg, local.Len())
		return nil

	case "head":
		// The tip of a scope's hash chain. Because each claim id covers its prev (SPEC §7.4), the
		// head transitively commits to the whole chain; publishing or `kton anchor`-ing it makes
		// every prior edit in the scope tamper-evident. This is the only chain-query the kernel
		// offers - resolution/walking beyond the tip is a consumer/cockpit concern.
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton head <scope-id>  (the seed/scope id, sha256:...)")
		}
		scope := args[0]
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		heads, chainLen, ok := r.Heads(scope)
		if !ok {
			return fmt.Errorf("no such scope %s (not a seed ingested in registry %s)", scope, dir())
		}
		// A withheld MIDDLE claim leaves later claims (possibly the real sealed head) unresolvable, so
		// the resolved tip below is only PROVISIONAL. Never present a truncated chain as sealed in silence.
		truncationWarning := func() {
			if n := r.Unresolved(scope); n > 0 {
				fmt.Printf("         !! POSSIBLE TRUNCATION: %d claim(s) name this scope but do not resolve (a missing prev)\n", n)
				fmt.Printf("         a withheld MIDDLE claim leaves its successors - maybe the sealed head - unreachable; the head above is PROVISIONAL, not proven final. Obtain the missing claim(s) and re-check.\n")
			}
		}
		if chainLen == 0 {
			fmt.Printf("scope:   %s  (no chained claims yet; the seed is its tip)\n", scope)
			fmt.Printf("head:    %s\n", heads[0])
			truncationWarning()
			return nil
		}
		if len(heads) == 1 {
			fmt.Printf("scope:   %s  (%d claim(s) chained)\n", scope, chainLen)
			fmt.Printf("head:    %s\n", heads[0])
			fmt.Printf("         publish or `kton anchor` this id to seal the chain: any edit to a prior claim changes it.\n")
			// TAIL truncation is undetectable in-band: dropping the last claim leaves a SHORTER but
			// internally-valid chain with nothing referencing the missing tip, so this tool cannot know a
			// later claim was withheld. "Sealed" therefore means a reader compares THIS tip against the
			// PUBLISHED / anchored head hash - only a mismatch reveals a withheld tail (cold-session
			// scope-truncation sibling; the middle-truncation case IS flagged above).
			fmt.Printf("         NOTE: this is the current KNOWN tip; a withheld LATER claim cannot be detected here - trust a head only by matching a published/anchored head hash.\n")
			truncationWarning()
			return nil
		}
		fmt.Printf("scope:   %s  (%d claims, BRANCHED into %d heads)\n", scope, chainLen, len(heads))
		for _, h := range heads {
			fmt.Printf("head:    %s\n", h)
		}
		// What a seal over a branched scope covers is NOT the kernel's to say: SPEC 7.4 leaves sealing
		// rules to consumers/aggregators, alongside `responsible` and parent->child registration. Report
		// the structure and the mechanical consequence of it; prescribe no remedy.
		fmt.Printf("         a linear chain has one head; multiple heads mean claims share a prev. Each head commits only to the claims on its own branch.\n")
		truncationWarning()
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

// The nekton federation server + HTTP mirror moved to the kton cockpit (cmd/kton): they open a
// port, which is cockpit surface, not kernel. The kernel imports no net/http and compiles to
// WebAssembly. Cross-registry replication: `kton mirror nekton <peer>`.
