package template_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
)

// TestAliasesResolveWithoutATemplateDirectory: aliases and templates are different things that
// happened to be loaded together, and `Load` fails when the template directory is absent — correctly,
// for a command about templates. Callers that only ever RESOLVE a term were falling back to a Set
// with no aliases at all, and the consequence reached signed RDF: `export --nanopub` and
// `nanopublish` take --aliases explicitly and have nothing to do with templates, so a publisher with
// no ./templates in the working directory silently emitted a DIFFERENT term IRI.
func TestAliasesResolveWithoutATemplateDirectory(t *testing.T) {
	dir := t.TempDir()
	aliases := filepath.Join(dir, "aliases.json")
	if err := os.WriteFile(aliases, []byte(`{"prefixes":{"qa":"https://kton.dev/v/qa/"},`+
		`"terms":{"reviewed":"qa:reviewed"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	set, err := template.LoadAliases(aliases)
	if err != nil {
		t.Fatalf("aliases must load with no template directory in sight: %v", err)
	}
	if got := set.Resolve("qa:reviewed"); got != "https://kton.dev/v/qa/reviewed" {
		t.Errorf("a CURIE did not resolve: %q", got)
	}
	if got := set.Resolve("reviewed"); got != "https://kton.dev/v/qa/reviewed" {
		t.Errorf("a term did not resolve: %q", got)
	}
	if n := len(set.Names()); n != 0 {
		t.Errorf("LoadAliases returned %d templates, want none", n)
	}

	// An absent alias file is no sugar, not an error.
	if _, err := template.LoadAliases(filepath.Join(dir, "absent.json")); err != nil {
		t.Errorf("an absent alias file should just mean no sugar: %v", err)
	}
	// A malformed one IS an error: resolving a CURIE to itself would sign a bare term as an IRI.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := template.LoadAliases(bad); err == nil {
		t.Error("a malformed alias file was accepted")
	}
}

// TestDuplicateTemplateNamesAreRefused: New keys by the declared name while ranging a Go map, so two
// files declaring one name made the winner depend on map iteration order — six consecutive
// `nekton templates` runs printed one predicate five times and the other once. `annotate --template
// qa/review` could therefore sign a DIFFERENT predicate run to run, and a predicate is covered by
// the claim id and signed.
func TestDuplicateTemplateNamesAreRefused(t *testing.T) {
	one := []byte(`{"name":"qa/review","predicate":"https://a.example/reviewed",` +
		`"fields":{"outcome":{"type":"string"}}}`)
	two := []byte(`{"name":"qa/review","predicate":"https://b.example/reviewed",` +
		`"fields":{"outcome":{"type":"string"}}}`)

	// Run it repeatedly: a map-order bug passes a single run most of the time, which is exactly how
	// this survived. If the refusal is ever not raised, one of these iterations catches it.
	for i := 0; i < 20; i++ {
		_, err := template.New(map[string][]byte{"a": one, "b": two}, nil)
		if err == nil {
			t.Fatalf("iteration %d: two templates declaring one name were accepted - which one "+
				"`--template qa/review` means then depends on map order", i)
		}
		if !strings.Contains(err.Error(), "declare the name") {
			t.Fatalf("wrong refusal: %v", err)
		}
	}
	// Distinct names are unaffected.
	if _, err := template.New(map[string][]byte{"a": one,
		"b": []byte(`{"name":"qa/other","predicate":"https://b.example/x","fields":{"o":{"type":"string"}}}`)},
		nil); err != nil {
		t.Errorf("two distinct names were refused: %v", err)
	}
}

// TestAStrayFileThatDoesNotUnmarshalIsAlsoSkipped: "one stray file does not disable the corpus" only
// covered files that unmarshal INTO a Template. A `.json` whose top level is an array, or with a
// field of the wrong type, still failed the whole Load - and those are the likeliest shapes of a
// stray config or data file, so the regression that change targets stayed reachable through them.
func TestAStrayFileThatDoesNotUnmarshalIsAlsoSkipped(t *testing.T) {
	for _, body := range []string{`[1,2,3]`, `{"name":{"a":1}}`, `"just a string"`} {
		t.Run(body, func(t *testing.T) {
			dir, aliases := setup(t)
			if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			set, err := template.Load(dir, aliases)
			if err != nil {
				t.Fatalf("a stray %s disabled the whole template surface: %v", body, err)
			}
			if _, ok := set.Get("qa/review"); !ok {
				t.Errorf("an unrelated template is gone; Names() = %v", set.Names())
			}
			if len(set.Skipped()) != 1 {
				t.Errorf("Skipped() = %v, want the one stray file named", set.Skipped())
			}
		})
	}
}

// TestAnEmptyFileIsAFile: `Spec` treated a present zero-length slice as an absent file. That
// conflated two different facts and got both wrong - an OPTIONAL empty file was silently dropped
// from what gets signed, and a REQUIRED one was refused as "missing required file field" although it
// had been supplied, sending the caller after an argument they gave.
//
// A zero-length artifact is an ordinary result: an empty log, a report with no findings, a clean
// diff. It has a content address like anything else - sha256 of no bytes is e3b0c442… - and dropping
// it loses evidence the caller passed.
func TestAnEmptyFileIsAFile(t *testing.T) {
	const emptySHA = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	tpl := []byte(`{"name":"qa/r","predicate":"https://kton.dev/v/x","fields":{` +
		`"opt":{"type":"file","role":"evidence"},"req":{"type":"file","role":"evidence","required":true}}}`)
	set, err := template.New(map[string][]byte{"a": tpl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	subj := "sha256:" + strings.Repeat("a", 64)

	hasEmpty := func(sp claim.Spec) bool {
		for _, e := range sp.Evidence {
			if m, ok := e.(map[string]any); ok && m["hash"] == emptySHA {
				return true
			}
		}
		return false
	}

	t.Run("an empty optional file is evidence, not silence", func(t *testing.T) {
		sp, err := set.Spec("qa/r", subj, nil, map[string][]byte{"opt": {}, "req": []byte("x")})
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if !hasEmpty(sp) {
			t.Errorf("the empty file was dropped; evidence = %v", sp.Evidence)
		}
	})

	t.Run("an empty required file satisfies the requirement", func(t *testing.T) {
		sp, err := set.Spec("qa/r", subj, nil, map[string][]byte{"req": {}})
		if err != nil {
			t.Fatalf("a supplied empty file was reported missing: %v", err)
		}
		if !hasEmpty(sp) {
			t.Errorf("the empty file was dropped; evidence = %v", sp.Evidence)
		}
	})

	t.Run("a genuinely absent required file is still missing", func(t *testing.T) {
		if _, err := set.Spec("qa/r", subj, nil, nil); err == nil {
			t.Error("an absent required file was accepted - not supplied and empty are different")
		}
	})
}
