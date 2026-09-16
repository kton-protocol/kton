package main

// annotate.go folds the template + alias layer into the binary, so a session with only the
// nekton binary + man page can record a structured, signed claim from a named template -
// no bash, no jq, no openssl (the old cli/nekton-annotate needed all three). It computes
// nothing about the world: it resolves a template (predicate, context, typed fields) and
// aliases (short name -> IRI) to full IRIs, hashes any file-typed field to a content ref,
// auto-stamps `when`, and hands a claimSpec to the one signing path (signClaim).
//
// The kernel prescribes NO templates and NO ontology: this reads whatever template/alias DATA
// it is pointed at (a directory that federates as a seeded subnekton - see docs). The binary
// carries the mechanism; the meaning travels as federated records.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

// looksLikeBrokenHash reports a value that is clearly a MANGLED content hash: it mentions "sha256" but is
// neither a clean sha256:<64-hex> nor a proper URI (scheme://…). Catches a bare "sha256" (no digest), a
// truncated "sha256:abc", and a doubled "<hex>:sha256:<hex>" - all of which used to register a claim that
// attaches to nothing (cold-session finding). A legit oci://…@sha256:… URI is allowed (it has "://").
func looksLikeBrokenHash(s string) bool {
	return strings.Contains(s, "sha256") && !isFullSha256(s) && !strings.Contains(s, "://")
}

// isFullSha256 reports whether s is a complete "sha256:" + 64 lowercase-hex id (not a truncated display hash).
func isFullSha256(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	h := s[len("sha256:"):]
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// resolvePredicateArg turns a `by predicate` value into the full predicate IRI that claims are stored
// under: a TEMPLATE name -> that template's (alias-resolved) predicate; a CURIE/term -> its IRI; a full
// IRI unchanged. (cold-session finding: `by predicate working-on` silently returned (none) because only
// the full URI matched, while `annotate --template` resolved the alias - an inconsistency that breaks
// coordination, since an empty result reads as "no one is working this step".)
func resolvePredicateArg(x string) string {
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	tset, err := template.Load(envOr("NEKTON_TEMPLATES", "./templates"), aliasesPath)
	if err != nil {
		// No template DIRECTORY is not the same as no ALIASES. Returning the raw argument here meant
		// that `nekton by predicate qa:reviewed` answered "(none)" whenever ./templates happened not
		// to exist - for a record the store held, and with the alias file sitting right there. That
		// is precisely the silent-empty-answer this function's comment above says it exists to
		// prevent. Aliases resolve on their own.
		tset, err = template.LoadAliases(aliasesPath)
		if err != nil {
			return x // not even a usable alias file: the argument is whatever the caller typed
		}
	}
	if t, ok := tset.Get(x); ok && t.Predicate != "" {
		return tset.Resolve(t.Predicate)
	}
	return tset.Resolve(x)
}

// mustTemplateSet is the resolver the RDF projections need. They only ever RESOLVE a CURIE, so a
// template DIRECTORY that cannot be read is not fatal here: the result is "no sugar" for templates.
// A malformed ALIAS file is a different matter and IS fatal - see below.
func mustTemplateSet(aliasesPath string) (template.Set, error) {
	tset, err := template.Load(envOr("NEKTON_TEMPLATES", "./templates"), aliasesPath)
	if err == nil {
		return tset, nil
	}
	// Fall back to the ALIASES ALONE, not to nothing. `Load` fails when ./templates is absent, which
	// is the normal case for the two callers of this function: `export --nanopub` and `nanopublish`
	// have nothing to do with templates and take --aliases explicitly. Falling back to an empty Set
	// dropped every prefix and term, and the same claim with the same alias file then published a
	// DIFFERENT term IRI depending on whether an unrelated directory existed:
	//
	//     ./templates present:  nk:outcome           = https://kton.dev/v/outcome
	//     ./templates absent:   <https://kton.dev/v/lab/outcome>
	//
	// into a signed nanopublication. A missing template directory must cost templates, not aliases.
	s, aerr := template.LoadAliases(aliasesPath)
	if aerr != nil {
		// A MALFORMED alias file stays FATAL, and the final `template.New(nil, nil)` fallback that
		// used to sit here is why it had stopped being so. With no aliases every CURIE resolves to
		// itself, so `qa:reviewed` went out as <qa:reviewed> - a bare term emitted as an IRI - and
		// `nanopublish` minted a permanent Trusty URI over that graph and exited 0.
		//
		// That is the exact harm LoadAliases' own doc calls out, reached silently in published,
		// signed RDF. An ABSENT alias file is still fine (LoadAliases returns an empty set for it);
		// what cannot be tolerated is a file that was meant to define meanings and does not parse.
		return template.Set{}, fmt.Errorf("alias file %s: %w\n"+
			"  Without it every CURIE resolves to itself, so a bare term like `qa:reviewed` would be\n"+
			"  emitted as an IRI into RDF that is published and permanent. Fix the file, or pass a\n"+
			"  different --aliases; an ABSENT one is fine and simply means no sugar", aliasesPath, aerr)
	}
	return s, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// annotate parses the CLI, resolves the template + aliases, builds a claimSpec, and signs it.
func annotate(args []string) error {
	var subject, foton, tmplName, out, by, keyPath, scope, prev, regDir, when string
	addFlag, printID := false, false
	tdir := envOr("NEKTON_TEMPLATES", "./templates")
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	set := map[string]string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add":
			addFlag = true
		case "--print-id":
			printID = true
		case "--registry":
			i++
			regDir = arg(args, i)
		case "--foton":
			i++
			foton = arg(args, i)
		case "--scope":
			i++
			scope = arg(args, i)
		case "--prev":
			i++
			prev = arg(args, i)
		case "--when":
			i++
			when = arg(args, i)
		case "--template":
			i++
			tmplName = arg(args, i)
		case "--templates-dir":
			i++
			tdir = arg(args, i)
		case "--aliases":
			i++
			aliasesPath = arg(args, i)
		case "--set":
			i++
			kv := arg(args, i)
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				return fmt.Errorf("--set expects key=value, got %q", kv)
			}
			set[kv[:eq]] = kv[eq+1:]
		case "--by":
			i++
			by = arg(args, i)
		case "--sign":
			i++
			keyPath = arg(args, i)
		case "-o":
			i++
			out = arg(args, i)
		default:
			// Any dash prefix, not just "--": `-x` fell through here and became the SUBJECT.
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag %q - `nekton annotate` takes flags --template, --set, "+
					"--foton, --sign, --by, --when, --scope, --prev, --templates-dir, --aliases, "+
					"--registry, --add, --print-id and -o", args[i])
			}
			// LAST-WINS on a SUBJECT. `annotate <a> <b> --template t` signed a claim about <b> and
			// said nothing. The argument for refusing this on `seed` was that a scope name is
			// identity; a claim's subject is what the claim is ABOUT, it is covered by the claim id,
			// and it is signed. It is not the smaller case.
			if subject != "" {
				return fmt.Errorf("`nekton annotate` takes ONE subject, got %q and %q - the subject is "+
					"what the claim is about and is covered by its id, so the wrong one signs a claim "+
					"about something else", subject, args[i])
			}
			subject = args[i]
		}
	}
	if tmplName == "" {
		return fmt.Errorf("usage: nekton annotate <subject|--foton FILE> --template <name|alias> --set k=v ... [--sign key.key] [--by ID] [-o out]")
	}

	// The template set is the package's, so this command and a linked cockpit resolve, validate and
	// shape a claim through one implementation.
	tset, err := template.Load(tdir, aliasesPath)
	if err != nil {
		return err
	}
	reportSkipped(tset)
	t, ok := tset.Get(tmplName)
	if !ok {
		return fmt.Errorf("no template %q in %s", tmplName, tdir)
	}

	// Subject: --foton resolves to the FOTON'S identity (matching plankton's foton id), so the
	// claim joins plankton's index - `nekton about <id>` and plankton lineage on the same id align.
	// (Cycle-1 finding: hashing the envelope FILE gave a third hash that joined to nothing.) If the
	// file is not a foton envelope, fall back to hashing its bytes.
	if foton != "" {
		// Mutually exclusive with a positional subject. Two positionals are refused a few lines up
		// because "the wrong one signs a claim about something else"; the same failure survived one
		// flag over, with `--foton` overwriting a subject the caller had typed and nothing said so.
		// The claim went out about the foton, exit 0.
		if subject != "" {
			return fmt.Errorf("both a subject (%q) and --foton %q were given - they name the same "+
				"thing, and --foton used to win silently. Pass one: the positional for a hash or URI, "+
				"--foton for an envelope whose foton id becomes the subject", subject, foton)
		}
		b, err := os.ReadFile(foton)
		if err != nil {
			// --foton takes a FILE (the foton envelope), so it can resolve the foton's id. A bare hash
			// here yields a misleading "open sha256:...: no such file"; say what to do instead.
			if strings.HasPrefix(foton, "sha256:") {
				return fmt.Errorf("--foton expects a FILE path (the foton envelope), not a bare hash; to use %s as the subject, pass it positionally: nekton annotate %s --template ...", foton, foton)
			}
			return err
		}
		subject = core.HashBytes(b) // fallback: the file's own byte hash
		// Resolve the foton id from EITHER shape: a bare DSSE envelope, OR a registry object file
		// {"fotonId":..,"envelope":{..}} - which is what a peer actually finds in PLANKTON_DIR/objects.
		// Earlier this handled only the bare envelope, so `--foton <registry-object>` silently subjected the
		// FILE hash (not the foton id) and the reproduction never registered (cold-session finding).
		idFrom := func(env core.Envelope) (string, bool) {
			if st, e := env.Statement(); e == nil {
				if f, e := st.ToFoton(); e == nil {
					if id, e := f.FotonID(); e == nil {
						return id, true
					}
				}
			}
			return "", false
		}
		var wrap struct {
			FotonID  string        `json:"fotonId"`
			Envelope core.Envelope `json:"envelope"`
		}
		if json.Unmarshal(b, &wrap) == nil && len(wrap.Envelope.Signatures) > 0 {
			if id, ok := idFrom(wrap.Envelope); ok { // registry object: derive from the nested envelope
				subject = id
			} else if wrap.FotonID != "" {
				subject = wrap.FotonID
			}
		} else {
			var env core.Envelope
			if json.Unmarshal(b, &env) == nil {
				if id, ok := idFrom(env); ok { // bare DSSE envelope
					subject = id
				}
			}
		}
	}
	if subject == "" {
		return fmt.Errorf("need a subject (sha256:... or a URI) or --foton FILE")
	}
	// A mangled hash (truncated, bare "sha256", or doubled prefix) silently attaches the claim to a subject
	// that never combines with anyone else's - reject it (cold-session finding: junk reproduces claims).
	if looksLikeBrokenHash(subject) {
		return fmt.Errorf("subject %q is not a valid sha256:<64-hex> (nor a URI) - a mangled hash attaches the claim to nothing; paste the complete foton id", subject)
	}

	// The template fields are walked by the template package, which is where that logic now lives so
	// a cockpit can link it instead of running this binary. Reading a `file` field's bytes stays HERE:
	// this caller has a filesystem, and the package deliberately does not assume one.
	values := map[string]string{}
	files := map[string][]byte{}
	for k, v := range set {
		if f, known := t.Fields[k]; known && f.Type == "file" {
			// An EMPTY value is "not supplied", not "read the file called empty string". A script
			// passing an unset $REPORT to an OPTIONAL file field used to sign fine; without this it
			// failed with `open : no such file or directory`, which names neither the variable nor
			// the fact that the field was optional. A REQUIRED field still fails, one step later and
			// with the template's own message, because Spec sees the field as absent.
			if v == "" {
				continue
			}
			b, rerr := os.ReadFile(v)
			if rerr != nil {
				return fmt.Errorf("file field %s: %w", k, rerr)
			}
			files[k] = b
			continue
		}
		values[k] = v
	}
	tspec, err := tset.Spec(tmplName, subject, values, files)
	if err != nil {
		return err
	}

	priv, ephemeral, err := signingKey(keyPath)
	if err != nil {
		return err
	}
	if by == "" {
		by = "key:" + keyidHex(priv.Public().(ed25519.PublicKey))
	}
	if ephemeral {
		humanOut(printID)("annotate: signer    keyid=%s (ephemeral - unlinkable; use --sign for attribution)\n", keyidHex(priv.Public().(ed25519.PublicKey)))
	}

	stamp, err := whenOr(when)
	if err != nil {
		return err
	}
	// tspec carries what the TEMPLATE decided: subject, resolved predicate and context, object and
	// evidence. What the command line decided - who signs, when, which scope - is added here.
	spec := tspec
	spec.By = by
	spec.When = stamp
	spec.Scope = scope // optional: place this claim in a (sub)nekton scope
	spec.Prev = prev   // the previous claim id in the scope (or the seed id for the first link)
	// ECHO the RESOLVED meaning before signing: the template + alias files are external, mutable, and
	// unauthenticated, so a MITM'd NEKTON_ALIASES/NEKTON_TEMPLATES could change what this signature
	// attests. Showing the resolved full-IRI predicate (and context) lets the signer catch a swapped
	// meaning; buildPredicate then refuses to sign anything that is not a full IRI (template/alias-trust).
	fmt.Fprintf(os.Stderr, "annotate: template=%s  predicate=%s", t.Name, spec.Predicate)
	if spec.Context != "" {
		fmt.Fprintf(os.Stderr, "  context=%s", spec.Context)
	}
	fmt.Fprintln(os.Stderr, "  (resolved via the alias file - confirm this is the meaning you intend)")
	// default a filename ONLY when we are actually writing one (not for --add without -o)
	if out == "" && !addFlag {
		// t.Name, not tmplName: resolution moved into tset.Get, so tmplName is still the ALIAS the
		// caller typed. `--template rev` wrote claim.rev.dsse.json where it wrote
		// claim.qa-review.dsse.json before. The stderr echo above already uses t.Name.
		out = "claim." + strings.ReplaceAll(t.Name, "/", "-") + ".dsse.json"
	}

	msg := humanOut(printID)
	msg("annotate: template %s  predicate %s\n", tmplName, spec.Predicate)
	if spec.Context != "" {
		msg("annotate: context   %s\n", spec.Context)
	}
	msg("annotate: subject   %s\n", subject)
	if spec.Scope != "" {
		msg("annotate: scope     %s\n", spec.Scope)
		prevShown := spec.Prev
		if prevShown == "" {
			prevShown = "(none)"
		}
		msg("annotate: prev      %s\n", prevShown)
	}
	if err := signClaim(spec, priv, out, addFlag, regDir, printID); err != nil {
		// The bare-term refusal (claim/spec.go) is right, but the case that actually triggers it is
		// almost always a MISSING alias file: the template resolved through an empty alias map and
		// came out as its own short name. The message describes the symptom and points at the
		// template, so that is where people go looking - one reader nearly filed it as a kernel
		// finding. The kernel deliberately does not know the path; the CLI does, so say it here.
		if strings.Contains(err.Error(), "bare term with no vocabulary") {
			return fmt.Errorf("%w\n(aliases resolved from %q - set NEKTON_ALIASES or --aliases if that is not your alias file)", err, aliasesPath)
		}
		return err
	}
	return nil
}

// listTemplates prints every template in the templates dir with its predicate and any aliases.
// With `--show <name>` (or a positional name/alias) it instead prints that template's fields -
// the cycle-1 gap where a session could not discover field names without reading the JSON.
func listTemplates(args []string) error {
	tdir := envOr("NEKTON_TEMPLATES", "./templates")
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	showName := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--templates-dir":
			i++
			tdir = arg(args, i)
		case "--aliases":
			i++
			aliasesPath = arg(args, i)
		case "--show":
			i++
			showName = arg(args, i)
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			// `templates` has NO subcommands. This used to take any positional as a template name and
			// let the LAST one win, which produced three bad outcomes at once: `templates ls` reported
			// `no template "ls"`, reading as a misspelled name rather than an unknown verb; the
			// documented `templates show <name>` appeared to work only because <name> overwrote
			// `show`, so any word would have done; and `templates HUHU <name>` behaved identically.
			// Anyone spot-checking docs/cli.md against the binary therefore had it CONFIRMED (#46).
			switch args[i] {
			case "ls", "list", "show", "search", "pull", "push", "add", "rm", "remove":
				return fmt.Errorf("`nekton templates` has no subcommand %q - it lists templates, or shows one with --show <name>.\n"+
					"`nekton man` is the command surface this build actually has", args[i])
			}
			if showName != "" {
				return fmt.Errorf("`nekton templates` takes at most one template name, got %q and %q", showName, args[i])
			}
			showName = args[i]
		}
	}
	// ONE reader of the template directory, the same the annotate path uses. Two readers would let
	// `templates` list something `annotate` then refuses - a template with no predicate, say - and
	// the difference would surface only when somebody tried to sign.
	tset, err := template.Load(tdir, aliasesPath)
	if err != nil {
		return err
	}
	reportSkipped(tset)
	if showName != "" {
		return showTemplate(tset, showName)
	}
	rev := tset.TemplateAliases()
	names := tset.Names()
	if len(names) == 0 {
		fmt.Printf("(no templates in %s)\n", tdir)
		return nil
	}
	for _, n := range names {
		t, ok := tset.Get(n)
		if !ok {
			continue
		}
		aliasStr := ""
		if al := rev[t.Name]; len(al) > 0 {
			aliasStr = "  (alias: " + strings.Join(al, ", ") + ")"
		}
		// A seed template has no predicate, and printing an empty column made it look like a broken
		// entry rather than a different KIND of entry. Say what it produces instead.
		what := tset.Resolve(t.Predicate)
		if t.IsSeed() {
			what = "(scope seed - no predicate; `nekton seed`, not `annotate`)"
		}
		fmt.Printf("%-28s %s%s\n", t.Name, what, aliasStr)
	}
	return nil
}

// showTemplate prints one template's predicate, context, and typed fields (name/type/required/role).
func showTemplate(tset template.Set, name string) error {
	t, ok := tset.Get(name)
	if !ok {
		return fmt.Errorf("no template %q", name)
	}
	fmt.Printf("template:  %s\n", t.Name)
	if t.IsSeed() {
		// Not a claim. Saying so HERE is the point: the fields below look like claim fields, and a
		// reader who takes them to `annotate` gets a refusal at signing time instead of an
		// explanation at reading time.
		fmt.Printf("produces:  a scope SEED (%s), not a claim - it opens a scope with\n", t.PredicateType)
		fmt.Printf("           scope/parent/responsible/genesis and has no predicate (SPEC §7.4).\n")
		fmt.Printf("           Build it with `nekton seed`.\n")
	} else {
		fmt.Printf("predicate: %s\n", tset.Resolve(t.Predicate))
	}
	if t.Context != "" {
		fmt.Printf("context:   %s\n", tset.Resolve(t.Context))
	}
	fmt.Printf("subject:   %s\n", t.Target)
	fmt.Printf("fields (use --set name=value):\n")
	for _, fn := range sortedFieldNames(t.Fields) {
		f := t.Fields[fn]
		role := f.Role
		if role == "" {
			role = "object"
		}
		req := "optional"
		if f.Required {
			req = "REQUIRED"
		}
		enum := ""
		if len(f.Values) > 0 {
			enum = "  {" + strings.Join(f.Values, "|") + "}"
		}
		// `file` fields say so: the value is a PATH here, and the bytes are what gets hashed. A
		// reader porting to the package hands bytes instead, and the package refuses a path - this
		// line is where that difference is first visible.
		note := ""
		if f.Type == "file" {
			note = "  (--set gives a PATH; its BYTES are hashed)"
		}
		fmt.Printf("  %-12s %-8s %-9s role=%s%s%s\n", fn, f.Type, req, role, enum, note)
	}
	return nil
}

func sortedFieldNames(m map[string]template.Field) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// reportSkipped names template-directory files that are not templates. Silence here is what let an
// alias file become a template called "aliases"; failing instead took the whole corpus down for one
// stray file. Naming them on stderr is the answer that does neither.
func reportSkipped(set template.Set) {
	for _, f := range set.Skipped() {
		fmt.Fprintf(os.Stderr, "note: skipping %q - it declares no fields, predicate or "+
			"predicateType, so it is not a template.\n", f)
	}
}
