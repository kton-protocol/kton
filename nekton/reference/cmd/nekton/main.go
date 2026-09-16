// Command nekton is the Phase-0 reference CLI for the nekton kernel: the commitment layer
// that records, signs-verifies, indexes, and federates SIGNED CLAIMS about plankton objects
// (and about other claims). It reuses plankton's shared `core` for canonicalization, hashing,
// and DSSE - the one allowed nekton -> plankton dependency. It never executes or reasons.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

const usage = `nekton - signed-claim commitment substrate (reference)

usage:
  nekton keygen <name> [--seed <64-hex>] [--force]  generate a signing identity (<name>.key/.pub)
      An existing key file is NEVER overwritten: replacing an identity destroys the only copy of
      its private seed. --force moves the old file to <name>.key.old rather than deleting it.
      An identical --seed is a no-op, so a reproducible snapshot can re-run.
      --seed <64-hex>                                 derive it from a seed, not the entropy pool, so a corpus or
                                                      snapshot rebuilds to the same record ids (fixtures only:
                                                      the key is only as strong as its seed)
  nekton pubkey <key.key|hex>                         print the public key hex (what verify/--trust-keys read)
  nekton keyid <key.pub|key.key|hex>                  print the keyid shown as by=key:<id> (map key -> signer)
  nekton seed <scope-name> --sign key.key [--add] [--registry D]  open a (sub)nekton scope; prints its scope id
      --print-id         print ONLY the bare id on stdout, human lines to stderr
                         (same contract as plankton author --print-id): ID=$(nekton seed … --print-id)
      --when <RFC3339>   pin the genesis timestamp. The scope id COVERS it, so this is what makes
                         a rebuilt corpus land on the same scope ids (default: now)
        [--by ID] [--parent <parentSeedId>] [-o out]      (scoped claims chain under it via --scope/--prev)
  nekton claim <spec.json> <key.key> [<out.dsse>] [--add] [--registry D]  author + sign a claim; --add ingests directly
      a subject in the spec is named with hash: "sha256:<hex>" - NOT with the digest map of the
      signed statement; an unknown field is refused, never dropped
  nekton annotate <subj|--foton F> --template <name> [--add] [--registry D]  author + sign a claim from a TEMPLATE
      --print-id         print ONLY the bare id on stdout, human lines to stderr
                         (same contract as plankton author --print-id): ID=$(nekton annotate … --print-id)
      --when <RFC3339>   pin the claim timestamp; the claim id covers it (default: now)
        --set k=v ... --sign key.key [--by ID] [-o out]   (aliases + auto timestamp; no jq/openssl)
  nekton templates [--show <name>]                    list templates + aliases; --show prints a template's fields
  nekton show <claim.dsse.json|sha256:id> [--json]             print a claim: subject, predicate, statement, signer
  nekton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>  verify a DSSE signature AND the
                                                      structure ingest requires (envelope FILE or a
                                                      registry id; pubkey: a .pub file or the hex)
                                                      exit 0 genuine+storable, 1 tampered, 2 wrong
                                                      key, 3 genuine but ingest would refuse it,
                                                      4 held here but DEFERRED - its prev/seed has
                                                      not arrived (incomplete, not invalid, §11)
  nekton records [--json] [--since N]                  every claim WITH its signed envelope: the
                                                      SPEC §12 sync(since) answer, over stdout
  nekton attach <sha256:id> --scheme S --file F [--media M]   bind external evidence to a record (SPEC §8.1):
                                                      a Sigstore bundle, a Rekor entry, an RFC 3161 token, an
                                                      X.509/CAdES or eIDAS signature. Stored, NEVER evaluated.
  nekton material <sha256:id> [--json]                what evidence is attached to a record
  nekton add <envelope.dsse.json> [--registry D]      ingest a signed claim (D or NEKTON_DIR)
  nekton about <subject> [--json]                     claims about a subject (hash "sha256:..." or uri)
  nekton by <signer|predicate|object> <value> [--json]  claims by signer keyid / predicate (template/CURIE/IRI) / object
  nekton head <scope-id> [--json]                              the tip of a scope's chain (publish/anchor it to seal history)
  nekton export [--title T] [out]                     serialize claims as JSON (for the Navigator join)
  nekton export --nanopub <claim.dsse.json> [-o out]  render a claim to its nanopublication (RDF/TriG) face
  nekton nanopublish <claim.dsse.json> [--rsa key.pem] [--creator IRI] [--trust-keys D] [-o out]
                                                      RSA-sign it + mint a Trusty URI. --trust-keys
                                                      decides what the PUBLISHED RDF asserts: with a
                                                      key that verifies, prov:wasAttributedTo; without
                                                      it, only nk:claimedSigner - and that is permanent
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
//
// waitingOnScope is non-empty when the record is HELD BUT DEFERRED: persisted, offered to peers, and
// kept out of every index because its prev/seed has not arrived. That is a third state, and it used
// to collapse into "not held" - a deferred id and a hash nobody ever heard of produced the same
// message and the same exit code. SPEC §12 makes the distinction normative.
func readEnvelopeOrID(arg string) (env core.Envelope, waitingOnScope string, chain chainState, err error) {
	if strings.HasPrefix(arg, "sha256:") {
		r, oerr := registry.Open(dir())
		if oerr != nil {
			return core.Envelope{}, "", chainUnchecked, oerr
		}
		if rec, ok := r.Claim(arg); ok {
			// RESOLVED is earned here and only here: being in the index means checkChain passed.
			return rec.Envelope, "", chainResolved, nil
		}
		if rec, scope, ok := r.DeferredClaim(arg); ok {
			if scope == "" {
				scope = "(an unnamed scope)"
			}
			return rec.Envelope, scope, chainDeferred, nil
		}
		return core.Envelope{}, "", chainUnchecked, fmt.Errorf("no claim %s in the registry (%s)", arg, dir())
	}
	// A FILE. This store was never asked about its scope or prev, so the honest answer is that the
	// chain was not checked - not that it resolved.
	e, rerr := readEnvelope(arg)
	return e, "", chainUnchecked, rerr
}

// chainState is what this store actually established about a claim's chain. UNCHECKED is a first
// class answer and the default, because the alternative - letting "not deferred" mean "resolved" -
// is how `verify <file>` came to assert that a store held a dependency it had never been asked
// about.
type chainState int

const (
	chainUnchecked chainState = iota
	chainResolved
	chainDeferred
)

// String is the machine-readable token for --json.
func (c chainState) String() string {
	switch c {
	case chainResolved:
		return "resolved"
	case chainDeferred:
		return "deferred"
	default:
		return "unchecked"
	}
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

// printClaimsJSON answers the RECORD-QUERY wire form. `about` and `by` are the `claims(subject |
// object | signer | predicate)` queries of SPEC §12, and the clause pins what comes back:
// `{ "records": [ <envelope> ... ] }` - the array elements ARE envelopes.
//
// This emitted a BARE ARRAY of `{claimId, envelope}` instead (#124): two departures at once, and
// the second is the one that bites. Wrapping an envelope in a field does not make the element an
// envelope, so a consumer decoding the declared contract read `payload=""`, `payloadType=""`,
// `signatures=0` - it could neither verify what it was handed nor re-ingest it, and nothing in the
// answer said why. It had to know a second, undocumented shape. plankton's record queries had the
// same defect and were fixed in d504bba; this is the nekton half of it.
//
// The claim id is not dropped, it MOVES: keyed by id beside the array, so a reader that wants it
// without re-deriving `sha256(canon(Statement))` still has it in one round trip. That placement is
// deliberate - a named id is what #57 asked for, and it cannot live inside an array whose elements
// the spec says are envelopes.
//
// Nothing is projected, ranked or interpreted beyond that: the caller decodes the payload exactly
// as the kernel does. The prose form above answers "which records, roughly"; a consumer of the
// claim axis needs the body, because a claim's meaning IS its body - the object it relates to does
// not appear in the rendered line at all.
func printClaimsJSON(recs []registry.Record) error {
	envs := make([]core.Envelope, 0, len(recs))
	summary := map[string]any{}
	for _, r := range recs {
		envs = append(envs, r.Envelope)
		e := map[string]any{}
		if st, _, err := claim.ParseEnvelope(r.Envelope); err == nil {
			if p, perr := st.ParsePredicate(); perr == nil && p != nil {
				e["predicate"], e["by"] = p.Predicate.Key(), p.By
			}
		}
		// The keyid is the envelope's SELF-DECLARED field and is not covered by the signature, so it
		// is labelled here exactly as the prose form labels it. A summary field called `signer`
		// would read as an established one.
		if len(r.Envelope.Signatures) > 0 {
			e["declaredKeyid"] = r.Envelope.Signatures[0].KeyID
		}
		summary[r.ClaimID] = e
	}
	b, err := json.MarshalIndent(map[string]any{"records": envs, "summary": summary}, "", "  ")
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

// validSubjectArg accepts what SPEC §7.3 calls a subject - a content address or a URI - and refuses
// anything else, so a malformed question is an error rather than an empty answer (SPEC §12).
func validSubjectArg(s string) (string, error) {
	if n, ok := core.NormalizeContentHash(s); ok {
		return n, nil
	}
	if i := strings.Index(s, ":"); i > 0 && !strings.HasPrefix(s, "sha") {
		return s, nil // a URI: it has a scheme, and the kernel treats the rest as opaque
	}
	return "", fmt.Errorf("%q is neither a sha256 content address nor a URI, so it is not a subject "+
		"this registry can be asked about.\n  An empty answer to a malformed question would be a "+
		"successful wrong answer (SPEC §12).", s)
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
		return keygen(args)

	case "pubkey":
		// Recover the .pub hex from a private key. Needed because an identity can be written by hand
		// (a bare 32-byte seed is a valid .key), and verify / --trust-keys / the viewer key dirs all
		// read the public half.
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton pubkey <key.key|hex>")
		}
		return pubkey(args[0])

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
		addFlag, regDir, printID := false, "", false
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--add":
				addFlag = true
			case "--print-id":
				printID = true
			case "--registry":
				i++
				if i < len(args) {
					regDir = args[i]
				}
			default:
				// A flag-shaped token is NOT a filename. `claim` takes its output as a third
				// POSITIONAL, while `seed` and `annotate` take `-o` - so one verb in three punishes
				// the habit the other two teach. `nekton claim spec.json k.key -o out.json` used to
				// write the envelope to a file literally named `-o`, drop the path the caller asked
				// for, and print `-> -o` as though that were the plan. Without `--add` the record
				// then existed nowhere the caller was looking.
				//
				// Succeeding while doing something else is worse than failing: `templates` learned
				// the same lesson in #45, where any positional was read as a template name.
				if strings.HasPrefix(args[i], "-") {
					return fmt.Errorf("unknown flag %q - `nekton claim` takes the output as a THIRD "+
						"POSITIONAL, not -o:\n  nekton claim <spec.json> <key.key> [<out.dsse.json>] "+
						"[--add] [--registry <dir>] [--print-id]\n(`seed` and `annotate` do take -o; "+
						"this verb does not)", args[i])
				}
				pos = append(pos, args[i])
			}
		}
		// out is optional when --add is given (ingest directly, no file)
		if len(pos) < 2 || (len(pos) < 3 && !addFlag) {
			return fmt.Errorf("usage: nekton claim <spec.json> <key.key> [<out.dsse.json>] [--add] [--registry <dir>] [--print-id]")
		}
		out := ""
		if len(pos) >= 3 {
			out = pos[2]
		}
		return authorClaim(pos[0], pos[1], out, addFlag, regDir, printID)

	case "seed":
		return seed(args)

	case "annotate":
		return annotate(args)

	case "templates":
		return listTemplates(args)

	case "show":
		return showClaim(args)

	case "records":
		// The §12 sync(since) query, over stdout rather than HTTP (#85).
		return records(args)

	case "attach":
		// SPEC §8.1: bind external evidence to a record by its CONTENT ADDRESS, never by filename.
		return attachMaterial(args)

	case "material":
		return listMaterial(args)

	case "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: nekton verify <envelope.dsse.json|sha256:id> <pubkey.pub|hex>")
		}
		env, deferredScope, chain, err := readEnvelopeOrID(args[0])
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
			// A valid signature says WHO signed these bytes, not that the substrate will accept the
			// claim. Exit 0 here is documented to mean BOTH - genuine and storable - so every way the
			// payload can fail to be storable must reach an exit, including failing to parse at all.
			// Anything that merely skips the structural check reports success by omitting a line, and
			// an omitted line is not something a caller can read.
			//
			// Exit 3, not 1 or 0: the signature verdict keeps its meaning (1 = invalid/tampered,
			// 2 = wrong key), so a structural refusal needs a code of its own.
			st, _, perr := claim.ParseEnvelope(env)
			if perr != nil {
				fmt.Printf("structure:       INVALID - %v\n", perr)
				fmt.Println("                 the signature is genuine; the payload is not a claim this substrate can store.")
				os.Exit(3)
			}
			p, pperr := st.ParsePredicate()
			if pperr != nil {
				fmt.Printf("structure:       INVALID - %v\n", pperr)
				fmt.Println("                 the signature is genuine; the claim is still one `add` refuses.")
				os.Exit(3)
			}
			if serr := st.Validate(p); serr != nil {
				fmt.Printf("structure:       INVALID - %v\n", serr)
				fmt.Println("                 the signature is genuine; the claim is still one `add` refuses.")
				os.Exit(3)
			}
			fmt.Println("structure:       VALID - the fields SPEC §7.2/§7.3 require are present")
			// Held, signed, well-formed - and its chain does not resolve HERE. Exit 4, because the
			// existing codes keep their meanings (1 = tampered, 2 = wrong key, 3 = unstorable) and
			// this is none of them: nothing is wrong with the record, something is missing from this
			// store. Reporting it as success would tell a caller the chain checks out; reporting it
			// as 3 would say the claim is malformed. Both are false, and both are what a reader
			// would have had to infer from prose before.
			switch chain {
			case chainDeferred:
				fmt.Printf("chain:           DEFERRED - held and offered to peers, but its prev/seed for scope %s\n", deferredScope)
				fmt.Println("                 has not arrived, so it is in no index here. Not a defect in the record:")
				fmt.Println("                 add the missing predecessor and it resolves (SPEC §11: incomplete, not invalid).")
				os.Exit(4)
			case chainResolved:
				fmt.Println("chain:           RESOLVED - this store holds what the claim depends on")
			default:
				// NOT CHECKED, and it must say so. This printed "RESOLVED - this store holds what the
				// claim depends on" for a claim read from a FILE, against a registry holding nothing:
				// the lookup that establishes `resolved` only runs on the registry-id path, and the
				// file path fell through to the same line. Nothing had been looked up.
				//
				// SPEC §8.1's read-path boundary is exactly this: presence is not a check, and a
				// kernel's own output MUST NOT carry a field that reads as a verification verdict. It
				// also inverted the exit contract - a caller branching on 4 got 0 for the one case it
				// most needs to catch.
				fmt.Println("chain:           NOT CHECKED - this envelope came from a file, so nothing was")
				fmt.Println("                 looked up. Pass the claim id instead to have this store")
				fmt.Println("                 resolve its scope and prev.")
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
			var ingested []string
			reAdded := map[string]bool{}
			deferred := 0
			for _, p := range paths {
				env, err := readEnvelope(p)
				if err != nil {
					refused = append(refused, fmt.Sprintf("%s: %v", p, err))
					continue
				}
				id, isNew, err := r.Add(env)
				if err != nil {
					// nekton's registry draws no transient/merit line the way plankton's ErrPersist
					// does, so every failure is reported by name and the exit is non-zero - the
					// caller decides what to do, rather than the import deciding silently.
					refused = append(refused, fmt.Sprintf("%s: %v", p, err))
					continue
				}
				// Every accepted record is classified after the batch, new or not: a re-added
				// deferred claim returns isNew=false and would otherwise be counted "already
				// present" for a store that answers no query for it.
				ingested = append(ingested, id)
				if !isNew {
					reAdded[id] = true
				}
			}
			// Classify AFTER the whole batch, never per record. A record deferred when it arrived
			// resolves the moment its dependency turns up later in the SAME batch - counting at
			// arrival reported it as deferred when by the end it was indexed, which is the mirror
			// of the defect this is fixing.
			//
			// INDEXED and DEFERRED are different outcomes and were reported as one: a record whose
			// seed or prev is absent is persisted and offered to peers but answers no query here, so
			// "indexed 2 claims, 0 refused (registry now holds 0)" was true of nothing - nothing was
			// indexed, nothing was refused, and a caller reading that plus exit 0 as a complete
			// import was wrong.
			for _, id := range ingested {
				switch {
				case func() bool { _, _, w := r.DeferredClaim(id); return w }():
					deferred++
				case reAdded[id]:
					present++
				default:
					added++
				}
			}
			for _, m := range refused {
				fmt.Fprintln(os.Stderr, "refused: "+m)
			}
			fmt.Printf("indexed %d claims, %d already present, %d deferred, %d refused  (registry now holds %d)\n",
				added, present, deferred, len(refused), r.Len())
			if deferred > 0 {
				fmt.Printf("  %d record(s) are held and offered to peers but answer no query here:\n", deferred)
				fmt.Printf("  their scope's seed or their prev has not arrived (SPEC §11: incomplete,\n")
				fmt.Printf("  not invalid). Add the missing predecessor and they resolve.\n")
			}
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
		_, deferredScope, isDeferred := r.DeferredClaim(id)
		switch {
		case isDeferred:
			// Checked BEFORE !isNew. A re-added deferred claim now returns isNew=false, so it fell
			// into "already present" and exited 0 - the same "indexed and deferred reported as one"
			// contradiction this branch exists to fix, reintroduced one case over. Present and
			// DEFERRED are different facts: the store holds it and answers no query for it.
			verb := "deferred claim"
			if !isNew {
				verb = "already present, still deferred:"
			}
			fmt.Printf("%s %s  (registry now holds %d claims)\n", verb, id, r.Len())
			fmt.Printf("  held and offered to peers, but its prev/seed for scope %s has not\n", deferredScope)
			fmt.Printf("  arrived, so it answers no query here (SPEC §11: incomplete, not invalid).\n")
		case !isNew:
			fmt.Printf("already present: claim %s\n", id)
		default:
			// Same distinction as the batch path: "indexed claim … (registry now holds 0 claims)"
			// contradicted itself in one line.
			if _, scope, waiting := r.DeferredClaim(id); waiting {
				fmt.Printf("deferred claim %s  (registry now holds %d claims)\n", id, r.Len())
				fmt.Printf("  held and offered to peers, but its prev/seed for scope %s has not\n", scope)
				fmt.Printf("  arrived, so it answers no query here (SPEC §11: incomplete, not invalid).\n")
			} else {
				fmt.Printf("indexed claim %s  (registry now holds %d claims)\n", id, r.Len())
			}
		}
		return nil

	case "about":
		args, asJSON := takeJSON(args)
		if len(args) != 1 {
			return fmt.Errorf("usage: nekton about <subject> [--json]  (hash \"sha256:...\" or uri)")
		}
		// SPEC §12: "An unrecognised or absent query parameter MUST be an error, never an empty
		// result: an empty answer to a malformed question is a successful wrong answer."
		//
		// `nekton about not-a-hash` used to print "(none)" and exit 0. A subject is a content address
		// or a URI; a bare word is neither, so the honest answer is not "nothing is said about it" but
		// "that is not a subject".
		subj, err := validSubjectArg(args[0])
		if err != nil {
			return err
		}
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		if asJSON {
			return printClaimsJSON(r.About(subj))
		}
		printClaims(r.About(subj))
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
		if args[0] == "signer" {
			// A keyid is 16 hex characters, or a public key that derives one. Anything else is a
			// malformed question (SPEC §12), not a signer who has said nothing.
			if k := keyidFromArg(args[1]); len(k) != 16 || strings.Trim(strings.ToLower(k), "0123456789abcdef") != "" {
				return fmt.Errorf("%q is not a signer keyid (16 hex characters), a .pub file, or a public key "+
					"hex.\n  An empty answer to a malformed question would be a successful wrong answer "+
					"(SPEC §12).\n  `nekton keyid <key.pub>` prints one.", args[1])
			}
		}
		switch args[0] {
		case "signer":
			recs = r.BySigner(keyidFromArg(args[1]))
		case "predicate":
			pred, perr := resolvePredicateArg(args[1])
			if perr != nil {
				return perr
			}
			recs = r.ByPredicate(pred)
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
			return fmt.Errorf("network peer %s - this repository carries no network transport.\n"+
				"  Mirror a local registry directory here; reaching a peer across a network is a\n"+
				"  cockpit capability. SPEC §12 leaves the transport unspecified: the queries and\n"+
				"  the wire form are normative, the binding is not, and `nekton records --json --since N`\n"+
				"  answers sync(since) over stdout.", peer)
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
		// There is no retry loop here any more, and that is a fix rather than a simplification.
		//
		// `Add` PERSISTS a claim whose seed or prev is missing and returns nil - unresolved is
		// INCOMPLETE, not invalid (SPEC §11), so it is stored and settles when its dependency
		// arrives. A missing dependency therefore never reached the old loop's error branch. Every
		// error that DID reach it was permanent (unparseable, unsigned, structurally invalid) or
		// environmental (a local write failure); retrying either is useless. So the loop retried
		// nothing that could heal, and then labelled whatever was left "unresolved (missing
		// dependency - an incomplete chain)". A local write failure was reported in exactly those
		// words, with exit 0. That is not imprecision, it is a wrong diagnosis of the one
		// class of error that could arrive.
		added, refused := 0, 0
		var refusedIDs []string
		for _, rec := range src.RawRecords() {
			_, isNew, err := local.Add(rec.Envelope)
			switch {
			case err == nil && isNew:
				added++
			case err == nil:
				// already held
			case errors.Is(err, registry.ErrPersist):
				return fmt.Errorf("mirror of %s FAILED after %d claim(s): could not write locally - "+
					"the local registry is incomplete and this is not a peer problem: %w", peer, added, err)
			default:
				refused++
				if len(refusedIDs) < 5 {
					refusedIDs = append(refusedIDs, rec.ClaimID)
				}
				fmt.Fprintf(os.Stderr, "warning: peer claim %s refused: %v\n", rec.ClaimID, err)
			}
		}
		msg := fmt.Sprintf("mirrored %s: %d new", peer, added)
		if refused > 0 {
			msg += fmt.Sprintf(", %d REFUSED as invalid (%s)", refused, strings.Join(refusedIDs, ", "))
		}
		fmt.Printf("%s; registry holds %d claim(s)\n", msg, local.Len())
		fmt.Fprintln(os.Stderr, "note: a claim whose seed or prev is not held yet is STORED and awaits it; "+
			"`nekton head <scope>` reports a scope that does not resolve.")
		if refused > 0 {
			return fmt.Errorf("%d peer claim(s) were refused - this copy is INCOMPLETE", refused)
		}
		return nil

	case "head":
		// The tip of a scope's hash chain. Because each claim id covers its prev (SPEC §7.4), the
		// head transitively commits to the whole chain; publishing or `kton anchor`-ing it makes
		// every prior edit in the scope tamper-evident. This is the only chain-query the kernel
		// offers - resolution/walking beyond the tip is a consumer/cockpit concern.
		headArgs, headJSON := takeJSON(args)
		if len(headArgs) != 1 {
			return fmt.Errorf("usage: nekton head <scope-id> [--json]  (the seed/scope id, sha256:...)")
		}
		scope := headArgs[0]
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		heads, chainLen, ok := r.Heads(scope)
		if !ok {
			return fmt.Errorf("no such scope %s (not a seed ingested in registry %s)", scope, dir())
		}
		if headJSON {
			// The head is what a consumer anchors or publishes, so it must be readable as data. Both
			// caveats travel with it as FIELDS rather than as prose a reader may skip: `unresolved`
			// (a withheld MIDDLE claim leaves later ones unreachable, so this tip is provisional) and
			// `branched` (each head then commits only to its own branch). `sealed` is deliberately
			// absent - a withheld LATER claim is undetectable in-band, and no field here could say so
			// honestly. That is settled by matching a published/anchored head, not by this command.
			return printJSONOut(map[string]any{
				"scope": scope, "heads": heads, "chainLength": chainLen,
				"branched": len(heads) > 1, "unresolved": r.Unresolved(scope),
			})
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
