package template_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

func setup(t *testing.T) (dir string, aliases string) {
	t.Helper()
	dir = t.TempDir()
	tmpl := map[string]any{
		"name": "qa/review", "target": "foton",
		"predicate": "qa:reviewed", "context": "ctx:qa",
		"fields": map[string]any{
			"outcome": map[string]any{"type": "enum", "required": true, "values": []string{"pass", "fail"}},
			"sop":     map[string]any{"type": "string"},
			"report":  map[string]any{"type": "file", "role": "evidence", "mediaType": "application/pdf"},
			"basedOn": map[string]any{"type": "ref"},
		},
	}
	b, _ := json.Marshal(tmpl)
	if err := os.WriteFile(filepath.Join(dir, "qa-review.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	a := map[string]any{
		"prefixes":  map[string]string{"qa": "https://kton.dev/v/qa/", "ctx": "https://kton.dev/ctx/"},
		"templates": map[string]string{"review": "qa/review"},
	}
	ab, _ := json.Marshal(a)
	// Beside the template directory, not inside it - the layout the example suite uses, and the one
	// Load's alias-file skip is written for.
	aliases = filepath.Join(t.TempDir(), "aliases.json")
	if err := os.WriteFile(aliases, ab, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, aliases
}

func TestSpecTakesBytesNotPaths(t *testing.T) {
	dir, ap := setup(t)
	s, err := template.Load(dir, ap)
	if err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("a", 64)
	pdf := []byte("%PDF-1.4 pretend")

	// THE refusal that makes this API safe to port to. The CLI form passed a PATH for a file field;
	// accepting a string here would hash the FILENAME and sign it as evidence - a claim that
	// verifies, resolves, and attests nothing anyone meant.
	t.Run("a file field given as a string is refused", func(t *testing.T) {
		_, err := s.Spec("qa/review", subject,
			map[string]string{"outcome": "pass", "report": "/tmp/report.pdf"}, nil)
		if err == nil {
			t.Fatal("a path was accepted for a file field - it would be hashed as though it were the file")
		}
		if !strings.Contains(err.Error(), "BYTES") {
			t.Errorf("refused, but the message does not say what to do instead: %v", err)
		}
	})

	t.Run("bytes become an evidence ref over their own hash", func(t *testing.T) {
		spec, err := s.Spec("qa/review", subject,
			map[string]string{"outcome": "pass", "sop": "SOP-1"},
			map[string][]byte{"report": pdf})
		if err != nil {
			t.Fatal(err)
		}
		if len(spec.Evidence) != 1 {
			t.Fatalf("evidence = %v, want one entry", spec.Evidence)
		}
		ev, ok := spec.Evidence[0].(map[string]any)
		if !ok {
			t.Fatalf("evidence entry is %T", spec.Evidence[0])
		}
		if ev["hash"] != core.HashBytes(pdf) {
			t.Errorf("evidence hash = %v, want the hash of the bytes passed in", ev["hash"])
		}
		if ev["mediaType"] != "application/pdf" {
			t.Errorf("the template's mediaType did not travel: %v", ev["mediaType"])
		}
		// The predicate is RESOLVED: what gets signed is the full IRI, never the CURIE.
		if spec.Predicate != "https://kton.dev/v/qa/reviewed" {
			t.Errorf("predicate = %q, want it resolved through the alias file", spec.Predicate)
		}
		if spec.Context != "https://kton.dev/ctx/qa" {
			t.Errorf("context = %q, want it resolved", spec.Context)
		}
	})

	t.Run("a template alias resolves", func(t *testing.T) {
		if _, ok := s.Get("review"); !ok {
			t.Error("the alias `review` did not resolve to qa/review")
		}
	})

	t.Run("required, enum and mangled-ref rules still hold", func(t *testing.T) {
		if _, err := s.Spec("qa/review", subject, map[string]string{"sop": "x"}, nil); err == nil {
			t.Error("a missing required field was accepted")
		}
		if _, err := s.Spec("qa/review", subject, map[string]string{"outcome": "maybe"}, nil); err == nil {
			t.Error("a value outside the template's enum was accepted")
		}
		if _, err := s.Spec("qa/review", subject,
			map[string]string{"outcome": "pass", "basedOn": "sha256:abc"}, nil); err == nil {
			t.Error("a truncated hash was accepted for a ref field - it links to no foton")
		}
	})

	t.Run("a field the template does not declare is refused, not dropped", func(t *testing.T) {
		if _, err := s.Spec("qa/review", subject,
			map[string]string{"outcome": "pass", "invented": "x"}, nil); err == nil {
			t.Error("an unknown field was dropped - a dropped field is signed away in silence")
		}
		if _, err := s.Spec("qa/review", subject, map[string]string{"outcome": "pass"},
			map[string][]byte{"invented": {1}}); err == nil {
			t.Error("unknown file bytes were dropped")
		}
	})

	t.Run("a mangled subject is refused", func(t *testing.T) {
		if _, err := s.Spec("qa/review", "sha256:abc", map[string]string{"outcome": "pass"}, nil); err == nil {
			t.Error("a mangled subject was accepted - the claim would attach to nothing")
		}
	})

	// A file in the template directory that is not a template used to parse into an EMPTY template:
	// json.Unmarshal drops members it does not know, so an alias file co-located with the templates
	// became a template named "aliases" with no predicate and no fields, and nothing said so. The
	// test does NOT assert on the predicate specifically: a seed template has none and must load.
	t.Run("a non-template in the template directory is refused, not absorbed", func(t *testing.T) {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "notatemplate.json"), []byte(`{"prefixes":{"a":"b"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := template.Load(d, filepath.Join(d, "aliases.json")); err == nil {
			t.Error("a file declaring no fields, predicate or predicateType was absorbed as a template")
		}
	})

	t.Run("a malformed alias file is an error, an absent one is not", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json") // OUTSIDE the template dir
		if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := template.Load(dir, bad); err == nil {
			t.Error("a malformed alias file was ignored - a CURIE would then resolve to itself and be signed")
		}
		if _, err := template.Load(dir, filepath.Join(dir, "absent.json")); err != nil {
			t.Errorf("an absent alias file should just mean no sugar: %v", err)
		}
	})
}

// A template name with a HYPHEN must survive the round trip through the directory. name -> file
// replaces "/" with "-", so the mapping is lossy: `pmx/model-role` and `pmx/model/role` are the same
// file. Reading "-" back as "/" renamed most of the example suite's templates - prov/derived-from,
// qa/tool-validation, election/vote-initialised - and Get then found none of them. A template's name
// is the one it declares; the filename is a fallback.
func TestHyphenatedNamesSurviveTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for file, name := range map[string]string{
		"pmx-model-role.json":            "pmx/model-role",
		"prov-derived-from.json":         "prov/derived-from",
		"election-vote-initialised.json": "election/vote-initialised",
	} {
		b, _ := json.Marshal(map[string]any{"name": name, "predicate": "https://e.org/" + name})
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := template.Load(dir, filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pmx/model-role", "prov/derived-from", "election/vote-initialised"} {
		if _, ok := s.Get(want); !ok {
			t.Errorf("Get(%q) found nothing; Names() = %v", want, s.Names())
		}
	}
}

// TestSeedTemplateLoadsAndIsRefusedAsAClaim pins the exact shape of a template this package once
// refused outright. `Load` rejected any template without a `predicate`, on the reasoning that a
// claim built from it would assert nothing - true for a claim, and wrong about the corpus: a
// scope-genesis template legitimately has no predicate, because it produces a SEED (SPEC §7.4),
// which carries scope/parent/responsible/genesis instead. One real template in the example suite is
// of that kind, so the guard made `nekton templates` fail on the shipped set entirely.
//
// That is the "gate that refuses the normal path" failure, in code I added while writing the gate.
// The refusal was not wrong, only misplaced: it belongs where a CLAIM is built, not where templates
// are read. This test holds both halves - the load must succeed, and Spec must still refuse - using
// the byte-for-byte shape of kton-examples/templates/election-vote-initialised.json.
func TestSeedTemplateLoadsAndIsRefusedAsAClaim(t *testing.T) {
	dir := t.TempDir()
	const seed = `{
	  "schema": "https://kton.dev/template/v0",
	  "name": "election/vote-initialised",
	  "kind": "scope-genesis",
	  "target": "scope",
	  "predicateType": "https://kton.dev/scope/v0",
	  "fields": {
	    "scope":       {"type": "string", "required": true, "maps": "seed.scope"},
	    "parent":      {"type": "ref",    "required": true, "maps": "seed.parent"},
	    "election":    {"type": "string", "required": true, "role": "context"},
	    "responsible": {"type": "idset",  "required": true, "maps": "seed.responsible"},
	    "roster":      {"type": "file",   "required": false, "role": "evidence"}
	  }
	}`
	if err := os.WriteFile(filepath.Join(dir, "election-vote-initialised.json"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := template.Load(dir, filepath.Join(t.TempDir(), "aliases.json"))
	if err != nil {
		t.Fatalf("a scope-genesis template must LOAD; the suite ships one: %v", err)
	}
	tpl, ok := set.Get("election/vote-initialised")
	if !ok {
		t.Fatalf("Get found nothing; Names() = %v", set.Names())
	}
	if !tpl.IsSeed() {
		t.Fatalf("IsSeed() = false for kind=%q predicateType=%q", tpl.Kind, tpl.PredicateType)
	}

	// Loading it is not permission to sign it as a claim. A caller that hands it to the claim path
	// must be told what it actually is, not handed a claim with an empty predicate.
	_, err = set.Spec("election/vote-initialised", "sha256:"+strings.Repeat("a", 64),
		map[string]string{"scope": "gemeinde-42", "parent": "sha256:" + strings.Repeat("b", 64),
			"election": "2026", "responsible": "CN=wahlleitung"}, nil)
	if err == nil {
		t.Fatal("Spec built a claim from a seed template - it would assert nothing")
	}
	for _, want := range []string{"SEED", "§7.4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q, so it does not say what to do instead: %v", want, err)
		}
	}
}
