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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kton.dev/plankton/core"
)

// aliasFile is the federated CURIE/term/template sugar (kton.dev/aliases/v0). All three maps
// are optional; an absent file just means "no sugar" (bare IRIs still work).
type aliasFile struct {
	Prefixes  map[string]string `json:"prefixes"`
	Terms     map[string]string `json:"terms"`
	Templates map[string]string `json:"templates"` // short name -> template name (this is the template alias)
}

// fieldDef is one typed slot in a template.
type fieldDef struct {
	Type      string   `json:"type"`      // string | enum | date | ref | file
	Role      string   `json:"role"`      // object (default) | evidence
	Required  bool     `json:"required"`  //
	MediaType string   `json:"mediaType"` // for file fields
	Values    []string `json:"values"`    // enum options (advisory; shown by `templates --show`)
}

// tmpl is a template: a predicate + optional context + typed fields, over opaque IRIs.
type tmpl struct {
	Name      string              `json:"name"`
	Target    string              `json:"target"` // file | foton | either (advisory)
	Predicate string              `json:"predicate"`
	Context   string              `json:"context"`
	Fields    map[string]fieldDef `json:"fields"`
}

func loadAliases(path string) aliasFile {
	var a aliasFile
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &a)
	}
	return a
}

// resolve turns a term / CURIE / IRI into a full IRI. A value containing "://" is already an
// IRI; a bare term resolves via `terms`; a `prefix:local` CURIE expands via `prefixes`.
func (a aliasFile) resolve(x string) string {
	if strings.Contains(x, "://") {
		return x
	}
	if v, ok := a.Terms[x]; ok {
		x = v
	}
	if i := strings.IndexByte(x, ':'); i >= 0 {
		if pfx, ok := a.Prefixes[x[:i]]; ok {
			return pfx + x[i+1:]
		}
	}
	return x
}

// resolveTemplate maps a template alias (short name) to its template name; a name that is not an
// alias is returned unchanged.
func (a aliasFile) resolveTemplate(name string) string {
	if v, ok := a.Templates[name]; ok {
		return v
	}
	return name
}

func templatePath(dir, name string) string {
	return filepath.Join(dir, strings.ReplaceAll(name, "/", "-")+".json")
}

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
	aliases := loadAliases(envOr("NEKTON_ALIASES", "./aliases.json"))
	name := aliases.resolveTemplate(x)
	if b, err := os.ReadFile(templatePath(envOr("NEKTON_TEMPLATES", "./templates"), name)); err == nil {
		var t tmpl
		if json.Unmarshal(b, &t) == nil && t.Predicate != "" {
			return aliases.resolve(t.Predicate)
		}
	}
	return aliases.resolve(x)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// annotate parses the CLI, resolves the template + aliases, builds a claimSpec, and signs it.
func annotate(args []string) error {
	var subject, foton, tmplName, out, by, keyPath, scope, prev, regDir string
	addFlag := false
	tdir := envOr("NEKTON_TEMPLATES", "./templates")
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	set := map[string]string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add":
			addFlag = true
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
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			subject = args[i]
		}
	}
	if tmplName == "" {
		return fmt.Errorf("usage: nekton annotate <subject|--foton FILE> --template <name|alias> --set k=v ... [--sign key.key] [--by ID] [-o out]")
	}

	aliases := loadAliases(aliasesPath)
	tmplName = aliases.resolveTemplate(tmplName)
	tb, err := os.ReadFile(templatePath(tdir, tmplName))
	if err != nil {
		return fmt.Errorf("no template %q in %s (%v)", tmplName, tdir, err)
	}
	var t tmpl
	if err := json.Unmarshal(tb, &t); err != nil {
		return fmt.Errorf("template %s: %w", tmplName, err)
	}

	// Subject: --foton resolves to the FOTON'S identity (matching plankton's foton id), so the
	// claim joins plankton's index - `nekton about <id>` and plankton lineage on the same id align.
	// (Cycle-1 finding: hashing the envelope FILE gave a third hash that joined to nothing.) If the
	// file is not a foton envelope, fall back to hashing its bytes.
	if foton != "" {
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
	var subj subjSpec
	if strings.HasPrefix(subject, "sha256:") {
		subj = subjSpec{Hash: subject}
	} else {
		subj = subjSpec{URI: subject}
	}

	// Walk the template fields, consuming --set values into object{} and evidence[].
	object := map[string]any{}
	var evidence []any
	for _, name := range sortedKeys(t.Fields) {
		f := t.Fields[name]
		val, ok := set[name]
		if !ok || val == "" {
			if f.Required {
				return fmt.Errorf("missing required field: %s", name)
			}
			continue
		}
		role := f.Role
		if role == "" {
			role = "object"
		}
		switch f.Type {
		case "file":
			b, err := os.ReadFile(val)
			if err != nil {
				return fmt.Errorf("file field %s: %w", name, err)
			}
			ref := map[string]any{"hash": core.HashBytes(b)}
			if f.MediaType != "" {
				ref["mediaType"] = f.MediaType
			}
			if role == "evidence" {
				evidence = append(evidence, ref)
			} else {
				object[name] = ref["hash"]
			}
		default: // string | enum | date | ref
			if f.Type == "ref" && looksLikeBrokenHash(val) {
				return fmt.Errorf("field %s = %q is not a valid sha256:<64-hex> - a mangled hash links to no foton; paste the complete id", name, val)
			}
			object[name] = val
		}
	}

	priv, ephemeral, err := signingKey(keyPath)
	if err != nil {
		return err
	}
	if by == "" {
		by = "key:" + keyidHex(priv.Public().(ed25519.PublicKey))
	}
	if ephemeral {
		fmt.Printf("annotate: signer    keyid=%s (ephemeral - unlinkable; use --sign for attribution)\n", keyidHex(priv.Public().(ed25519.PublicKey)))
	}

	spec := claimSpec{
		Subject:   []subjSpec{subj},
		Predicate: aliases.resolve(t.Predicate),
		By:        by,
		When:      time.Now().UTC().Format(time.RFC3339),
		Scope:     scope, // optional: place this claim in a (sub)nekton scope
		Prev:      prev,  // the previous claim id in the scope (or the seed id for the first link)
	}
	if t.Context != "" {
		spec.Context = aliases.resolve(t.Context)
	}
	// ECHO the RESOLVED meaning before signing: the template + alias files are external, mutable, and
	// unauthenticated, so a MITM'd NEKTON_ALIASES/NEKTON_TEMPLATES could change what this signature
	// attests. Showing the resolved full-IRI predicate (and context) lets the signer catch a swapped
	// meaning; buildPredicate then refuses to sign anything that is not a full IRI (template/alias-trust).
	fmt.Fprintf(os.Stderr, "annotate: template=%s  predicate=%s", tmplName, spec.Predicate)
	if spec.Context != "" {
		fmt.Fprintf(os.Stderr, "  context=%s", spec.Context)
	}
	fmt.Fprintln(os.Stderr, "  (resolved via the alias file - confirm this is the meaning you intend)")
	if len(object) > 0 {
		spec.Object = object
	}
	if len(evidence) > 0 {
		spec.Evidence = evidence
	}
	// default a filename ONLY when we are actually writing one (not for --add without -o)
	if out == "" && !addFlag {
		out = "claim." + strings.ReplaceAll(tmplName, "/", "-") + ".dsse.json"
	}

	fmt.Printf("annotate: template %s  predicate %s\n", tmplName, spec.Predicate)
	if spec.Context != "" {
		fmt.Printf("annotate: context   %s\n", spec.Context)
	}
	fmt.Printf("annotate: subject   %s\n", subject)
	if spec.Scope != "" {
		fmt.Printf("annotate: scope     %s\n", spec.Scope)
		prevShown := spec.Prev
		if prevShown == "" {
			prevShown = "(none)"
		}
		fmt.Printf("annotate: prev      %s\n", prevShown)
	}
	return signClaim(spec, priv, out, addFlag, regDir)
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
			if !strings.HasPrefix(args[i], "--") {
				showName = args[i]
			}
		}
	}
	aliases := loadAliases(aliasesPath)
	if showName != "" {
		return showTemplate(tdir, aliases, showName)
	}
	// invert template aliases: template name -> [short names]
	rev := map[string][]string{}
	for short, full := range aliases.Templates {
		rev[full] = append(rev[full], short)
	}
	entries, err := os.ReadDir(tdir)
	if err != nil {
		return fmt.Errorf("no templates dir %s (%v)", tdir, err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(tdir, e.Name()))
		if err != nil {
			continue
		}
		var t tmpl
		if json.Unmarshal(b, &t) != nil || t.Name == "" {
			continue
		}
		found++
		al := rev[t.Name]
		sort.Strings(al)
		aliasStr := ""
		if len(al) > 0 {
			aliasStr = "  (alias: " + strings.Join(al, ", ") + ")"
		}
		fmt.Printf("%-28s %s%s\n", t.Name, aliases.resolve(t.Predicate), aliasStr)
	}
	if found == 0 {
		fmt.Printf("(no templates in %s)\n", tdir)
	}
	return nil
}

// showTemplate prints one template's predicate, context, and typed fields (name/type/required/role).
func showTemplate(tdir string, aliases aliasFile, name string) error {
	name = aliases.resolveTemplate(name)
	b, err := os.ReadFile(templatePath(tdir, name))
	if err != nil {
		return fmt.Errorf("no template %q in %s", name, tdir)
	}
	var t tmpl
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	fmt.Printf("template:  %s\n", t.Name)
	fmt.Printf("predicate: %s\n", aliases.resolve(t.Predicate))
	if t.Context != "" {
		fmt.Printf("context:   %s\n", aliases.resolve(t.Context))
	}
	fmt.Printf("subject:   %s\n", t.Target)
	fmt.Printf("fields (use --set name=value):\n")
	for _, fn := range sortedKeys(t.Fields) {
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
		fmt.Printf("  %-12s %-8s %-9s role=%s%s\n", fn, f.Type, req, role, enum)
	}
	return nil
}

func sortedKeys(m map[string]fieldDef) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
