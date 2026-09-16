// Package template turns a template plus a set of values into a claim spec.
//
// It is the one thing a cockpit must do and the one thing it could not link. Everything else it
// needs is already a package: authoring (claim.SignWith, foton.SignWith), verifying, reading,
// material, scopes. This was only inside `nekton annotate`, so a cockpit had to run a binary and
// parse its output for the single step where a typed field set becomes a signed statement.
//
// NO FILE SYSTEM, deliberately. A `file` field's BYTES are passed in; where they came from - a path,
// an upload, a browser File object - is the caller's business and only the caller knows. The first
// cut of this API read them from disk, which compiles under js/wasm and fails at runtime: the one
// function a browser cockpit needs would have been the one it could not use, in a project whose CI
// builds both kernels for that target. Reading bytes is the caller's half; validating and shaping
// them is this package's.
package template

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// Field is one typed slot in a template.
type Field struct {
	Type      string   `json:"type"`      // string | enum | date | ref | file
	Role      string   `json:"role"`      // object (default) | evidence
	Required  bool     `json:"required"`  //
	MediaType string   `json:"mediaType"` // for file fields
	Values    []string `json:"values"`    // enum options
}

// Template is a predicate + optional context + typed fields, over opaque IRIs. The kernel never
// interprets the predicate (SPEC §7.1); a template is application vocabulary with a shape.
type Template struct {
	Name   string `json:"name"`
	Target string `json:"target"` // file | foton | scope | either (advisory)
	// Kind and PredicateType say what a template PRODUCES. A claim template carries a Predicate; a
	// `scope-genesis` one carries predicateType = scope/v0 and produces a SEED instead, which has no
	// predicate at all - it has scope, parent, responsible, genesis (SPEC §7.4). A caller must be
	// able to tell them apart before asking for a claim spec.
	Kind          string           `json:"kind"`
	PredicateType string           `json:"predicateType"`
	Predicate     string           `json:"predicate"`
	Context       string           `json:"context"`
	Fields        map[string]Field `json:"fields"`
}

// IsSeed reports whether this template produces a scope SEED rather than a claim. Spec refuses one:
// a seed is a different statement shape and a different signing path.
func (t Template) IsSeed() bool {
	return t.Kind == "scope-genesis" || t.PredicateType == claim.ScopePredicateType
}

// aliasFile is the federated CURIE/term/template sugar (kton.dev/aliases/v0). All three maps are
// optional; an absent file just means "no sugar" - bare IRIs still work.
type aliasFile struct {
	Prefixes  map[string]string `json:"prefixes"`
	Terms     map[string]string `json:"terms"`
	Templates map[string]string `json:"templates"` // short name -> template name
}

// Set is a group of templates plus the alias file that resolves the CURIEs in them. It is a VALUE:
// once built it touches nothing, so the same Set serves a process with a disk and a browser that
// fetched the same bytes.
type Set struct {
	templates map[string]Template
	aliases   aliasFile
	origin    string // where these came from, for error messages only
	// skipped names files in the template source that are not templates. They are reported rather
	// than absorbed (which was silent) or fatal (which took the corpus down for one stray file).
	skipped []string
}

// New builds a Set from bytes the caller already has - a fetch, a bundle, an embedded asset, an
// upload. templates is keyed by template NAME ("qa/review"); aliases may be nil, which means no
// sugar and bare IRIs only.
//
// This is the constructor a browser cockpit uses. Load is the same thing over a directory.
func New(templates map[string][]byte, aliases []byte) (Set, error) {
	return newWithOrigin(templates, aliases, "the supplied templates")
}

// newWithOrigin is New with a caller-supplied name for the source, used only in error messages.
// Load passes the directory, because "two templates in ./templates declare the name X" sends a
// reader somewhere and "two templates in the supplied templates" does not - and Load could not set
// it after the fact, since the error naming it is produced in here.
func newWithOrigin(templates map[string][]byte, aliases []byte, origin string) (Set, error) {
	s := Set{templates: map[string]Template{}, origin: origin}
	if len(aliases) > 0 {
		if err := json.Unmarshal(aliases, &s.aliases); err != nil {
			return Set{}, fmt.Errorf("alias file: %w - continuing without it would resolve a CURIE to "+
				"itself and sign it as though it were an IRI", err)
		}
	}
	for key, b := range templates {
		var t Template
		if err := json.Unmarshal(b, &t); err != nil {
			// SKIPPED, like a file that parses but declares nothing. "One stray file does not
			// disable the corpus" only covered files that unmarshal INTO a Template, so a `.json`
			// whose top level is an array, or with a field of the wrong type, still failed the whole
			// Load - and those are the likeliest shapes of a stray config or data file. The
			// regression that change targets was still reachable through them.
			s.skipped = append(s.skipped, key)
			continue
		}
		// A template's NAME is the one it declares. The key it arrived under - a filename, a fetch
		// path - is only a fallback, and a lossy one: `a/b-c` and `a/b/c` reach the same file.
		name := t.Name
		if name == "" {
			name = key
			t.Name = key
		}
		// A file here that is not a template must not be ABSORBED as one. json.Unmarshal drops
		// members it does not know, so an alias file co-located with the templates parsed into an
		// empty Template and joined the set under its filename, silently.
		//
		// SKIPPED, not fatal. Refusing the whole set for one stray file took the entire template
		// surface down - `templates`, `--show`, and `annotate --template qa/review`, a template with
		// nothing to do with the offending file - so one editor backup made a working corpus
		// unusable for signing. That is the gate-refuses-the-normal-path failure, and this guard had
		// it in the same commit that fixed another instance of it.
		//
		// Skipping fixes what the guard was actually for: the file is not absorbed, and it is not
		// silent. A malformed ALIAS file stays fatal - that one changes what a CURIE means, and
		// resolving one to itself would sign a bare term as though it were an IRI.
		//
		// The discriminator is NOT "has a predicate": a scope-genesis template legitimately has none,
		// because it produces a SEED (SPEC §7.4). What every template does declare is somewhere to
		// put values or something to assert; a file with neither is not one.
		if len(t.Fields) == 0 && t.Predicate == "" && t.PredicateType == "" {
			s.skipped = append(s.skipped, key)
			continue
		}
		// A name collision is REFUSED, not resolved by luck. `templates` is a map and New ranges it,
		// so two files declaring one name made the winner depend on map iteration order: six
		// consecutive `nekton templates` runs printed one predicate five times and the other once,
		// which means `annotate --template qa/review` could sign a DIFFERENT predicate run to run.
		// A predicate is covered by the claim id and is signed.
		//
		// The old filename->name mapping was 1:1 by construction, so this could not arise; keying on
		// the declared name is what makes it possible, and that key was introduced to stop hyphenated
		// names being mangled. Both properties are wanted, so the collision is named instead of
		// silently broken either way.
		if prev, dup := s.templates[name]; dup {
			return Set{}, fmt.Errorf("two templates in %s declare the name %q (predicates %q and %q) - "+
				"which one `--template %s` means would depend on map order, and a predicate is signed",
				s.origin, name, prev.Predicate, t.Predicate, name)
		}
		s.templates[name] = t
	}
	return s, nil
}

// LoadAliases reads ONLY the alias file, with no template directory involved. The resulting Set has
// no templates and resolves CURIEs, terms and prefixes exactly as a full one does.
//
// It exists because aliases and templates are different things that happened to be loaded together.
// `Load` fails when the template directory is absent - correctly, for a command about templates -
// and callers that only ever RESOLVE a term were falling back to a Set with no aliases at all. The
// consequence was not a missing convenience: `export --nanopub` and `nanopublish` take `--aliases`
// explicitly and have nothing to do with templates, so a publisher with no ./templates in the
// working directory silently emitted a DIFFERENT term IRI into signed RDF, and `by predicate
// qa:reviewed` answered "(none)" for a record the store held.
//
// An absent alias file is not an error here either - it means no sugar - but a malformed one is,
// for the same reason it is in Load: resolving a CURIE to itself would sign a bare term as though
// it were an IRI.
func LoadAliases(aliasPath string) (Set, error) {
	b, err := os.ReadFile(aliasPath)
	if err != nil {
		if os.IsNotExist(err) {
			return New(nil, nil)
		}
		return Set{}, fmt.Errorf("alias file %s: %w", aliasPath, err)
	}
	return New(nil, b)
}

// Load is New over a directory: every *.json in templateDir is a template (the on-disk `a-b.json`
// is the template `a/b`), and aliasPath is the alias file.
//
// An absent alias file is NOT an error - it means no sugar. A malformed one IS: silently continuing
// with an empty alias map would resolve a CURIE to itself and sign a bare `qa:reviewed` as though it
// were an IRI.
func Load(templateDir, aliasPath string) (Set, error) {
	var aliases []byte
	if b, err := os.ReadFile(aliasPath); err == nil {
		aliases = b
	} else if !os.IsNotExist(err) {
		return Set{}, fmt.Errorf("alias file %s: %w", aliasPath, err)
	}
	raw := map[string][]byte{}
	ents, err := os.ReadDir(templateDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Said once and plainly. "no template X in ./templates" would be the wrong diagnosis:
			// nothing is missing FROM a directory that is not there, and the reader would go looking
			// for a template instead of for the path.
			return Set{}, fmt.Errorf("no template directory at %s - set NEKTON_TEMPLATES or pass "+
				"--templates-dir", templateDir)
		}
		return Set{}, fmt.Errorf("template directory %s: %w", templateDir, err)
	}
	aliasBase := filepath.Base(aliasPath)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		// The alias file is not a template. When the two live in one directory it would otherwise be
		// parsed as one - and it PARSES, into a Template with no predicate and no fields, because
		// unknown members are dropped. A silent empty template is worse than a loud refusal.
		if n == aliasBase {
			continue
		}
		b, err := os.ReadFile(filepath.Join(templateDir, n))
		if err != nil {
			return Set{}, err
		}
		// Keyed by the FILENAME here; New re-keys by the template's declared `name`. The filename
		// cannot be inverted: name -> file replaces "/" with "-", so `pmx/model-role` and
		// `pmx/model/role` are the same file, and reading `-` back as `/` renames most templates in
		// the example suite. The name a template declares is the name it has.
		raw[strings.TrimSuffix(n, ".json")] = b
	}
	s, err := newWithOrigin(raw, aliases, templateDir)
	if err != nil {
		return Set{}, err
	}
	return s, nil
}

// Names lists the templates in this Set, sorted.
func (s Set) Names() []string {
	out := make([]string, 0, len(s.templates))
	for n := range s.templates {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns a template by name, resolving a template alias first.
func (s Set) Get(name string) (Template, bool) {
	t, ok := s.templates[s.resolveTemplate(name)]
	return t, ok
}

// Prefixes returns the CURIE prefix map this Set resolves with. An RDF projection needs it to
// re-abbreviate a full IRI on the way out, which is the inverse of what Resolve does on the way in -
// and both must come from the same file, or a term expands to one IRI and prints as another.
func (s Set) Prefixes() map[string]string {
	out := make(map[string]string, len(s.aliases.Prefixes))
	for k, v := range s.aliases.Prefixes {
		out[k] = v
	}
	return out
}

// TemplateAliases maps each template name to the short names that resolve to it. A lister wants the
// inverse of the alias map, and building it from a Set keeps one reader of that file rather than two.
func (s Set) TemplateAliases() map[string][]string {
	rev := map[string][]string{}
	for short, full := range s.aliases.Templates {
		rev[full] = append(rev[full], short)
	}
	for _, v := range rev {
		sort.Strings(v)
	}
	return rev
}

// Resolve turns a term / CURIE / IRI into a full IRI, the way this Set's alias file says. Exported
// because a caller that wants to SHOW what it is about to sign needs the resolved meaning: the
// template and alias files are external, mutable and unauthenticated, so the resolved predicate is
// what the signature will actually attest.
func (s Set) Resolve(x string) string {
	if strings.Contains(x, "://") {
		return x
	}
	if v, ok := s.aliases.Terms[x]; ok {
		x = v
	}
	if i := strings.IndexByte(x, ':'); i >= 0 {
		if pfx, ok := s.aliases.Prefixes[x[:i]]; ok {
			return pfx + x[i+1:]
		}
	}
	return x
}

func (s Set) resolveTemplate(name string) string {
	if v, ok := s.aliases.Templates[name]; ok {
		return v
	}
	return name
}

// Spec validates values against a template's fields and returns the claim spec to sign.
//
// values carries every field except `file`; files carries the BYTES of each `file` field, keyed by
// field name. The caller knows which is which - Get(name) hands it the template.
//
// A `file` field supplied in values is an ERROR rather than a coercion. Porting from the CLI form,
// where the value was a path, would otherwise hash the FILENAME and sign that as evidence: a claim
// that verifies, resolves and means nothing. Refusing is the only way that shows up.
func (s Set) Spec(name, subject string, values map[string]string, files map[string][]byte) (claim.Spec, error) {
	t, ok := s.Get(name)
	if !ok {
		return claim.Spec{}, fmt.Errorf("no template %q in %s", name, s.origin)
	}
	if t.IsSeed() {
		return claim.Spec{}, fmt.Errorf("template %q produces a scope SEED, not a claim: it has no "+
			"predicate, and a seed carries scope/parent/responsible/genesis instead (SPEC §7.4). "+
			"Build it with the seed path, not from a claim spec", t.Name)
	}
	if strings.TrimSpace(t.Predicate) == "" {
		return claim.Spec{}, fmt.Errorf("template %q has no predicate - a claim built from it would "+
			"assert nothing", t.Name)
	}
	if subject == "" {
		return claim.Spec{}, fmt.Errorf("a claim needs a subject: a sha256:<64-hex> content address or a URI")
	}
	var subj claim.SubjectSpec
	if strings.HasPrefix(subject, "sha256:") {
		if _, ok := core.NormalizeContentHash(subject); !ok {
			return claim.Spec{}, fmt.Errorf("subject %q is not a valid sha256:<64-hex> - a mangled hash "+
				"attaches the claim to nothing", subject)
		}
		subj = claim.SubjectSpec{Hash: subject}
	} else {
		subj = claim.SubjectSpec{URI: subject}
	}

	object := map[string]any{}
	var evidence []any
	for _, fname := range sortedKeys(t.Fields) {
		f := t.Fields[fname]
		role := f.Role
		if role == "" {
			role = "object"
		}
		if f.Type == "file" {
			if _, wrong := values[fname]; wrong {
				return claim.Spec{}, fmt.Errorf("field %q is a `file` field: pass its BYTES in files[%q], "+
					"not a string in values. A path given here would be hashed as though it were the "+
					"file, and the claim would verify while attesting the filename", fname, fname)
			}
			b, ok := files[fname]
			if !ok || len(b) == 0 {
				if f.Required {
					return claim.Spec{}, fmt.Errorf("missing required file field: %s", fname)
				}
				continue
			}
			ref := map[string]any{"hash": core.HashBytes(b)}
			if f.MediaType != "" {
				ref["mediaType"] = f.MediaType
			}
			if role == "evidence" {
				evidence = append(evidence, ref)
			} else {
				object[fname] = ref["hash"]
			}
			continue
		}
		if _, wrong := files[fname]; wrong {
			return claim.Spec{}, fmt.Errorf("field %q is not a `file` field, so bytes in files[%q] would "+
				"be ignored - pass its value in values", fname, fname)
		}
		val, ok := values[fname]
		if !ok || val == "" {
			if f.Required {
				return claim.Spec{}, fmt.Errorf("missing required field: %s", fname)
			}
			continue
		}
		if f.Type == "ref" && looksLikeBrokenHash(val) {
			return claim.Spec{}, fmt.Errorf("field %s = %q is not a valid sha256:<64-hex> - a mangled "+
				"hash links to no foton; paste the complete id", fname, val)
		}
		if f.Type == "enum" && len(f.Values) > 0 && !contains(f.Values, val) {
			return claim.Spec{}, fmt.Errorf("field %s = %q is not one of the template's values %v",
				fname, val, f.Values)
		}
		object[fname] = val
	}
	// A value for a field the template does not declare is refused rather than dropped. A dropped
	// field is signed away in silence, and the caller believes it said something it did not.
	for k := range values {
		if _, known := t.Fields[k]; !known {
			return claim.Spec{}, fmt.Errorf("template %q has no field %q", t.Name, k)
		}
	}
	for k := range files {
		if _, known := t.Fields[k]; !known {
			return claim.Spec{}, fmt.Errorf("template %q has no field %q", t.Name, k)
		}
	}

	spec := claim.Spec{
		Subject:   []claim.SubjectSpec{subj},
		Predicate: s.Resolve(t.Predicate),
	}
	if t.Context != "" {
		spec.Context = s.Resolve(t.Context)
	}
	if len(object) > 0 {
		spec.Object = object
	}
	if len(evidence) > 0 {
		spec.Evidence = evidence
	}
	return spec, nil
}

// looksLikeBrokenHash reports a value that is clearly a MANGLED content hash: it mentions "sha256"
// but is neither a clean sha256:<64-hex> nor a proper URI. Catches a bare "sha256", a truncated
// "sha256:abc" and a doubled "<hex>:sha256:<hex>" - each of which registers a claim attached to
// nothing. A legitimate oci://…@sha256:… URI is allowed: it has "://".
func looksLikeBrokenHash(s string) bool {
	if !strings.Contains(s, "sha256") || strings.Contains(s, "://") {
		return false
	}
	_, ok := core.NormalizeContentHash(s)
	return !ok
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]Field) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Skipped names the files in the template source that were not templates. A caller SHOULD print
// these: absorbing them silently is how an alias file became a template named "aliases", and
// refusing the whole directory for one of them is how a stray editor backup made every template
// unusable. Naming them is the middle answer.
func (s Set) Skipped() []string { return s.skipped }
