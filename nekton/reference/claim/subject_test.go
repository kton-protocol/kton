package claim_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

// A subject that names nothing is a claim about nothing. It used to sign, verify, index and attach
// without a word of warning, while `about <hash>` could never reach it - because it is about no
// hash. The trap: the authoring spec spells a subject `hash: "sha256:..."` and the SIGNED statement
// spells it `digest: {sha256: ...}` (SPEC §7.3). Anyone reading a signed statement and reasoning
// backwards writes `digest` in the spec, encoding/json drops the field it does not know, and
// SubjectsOf renders `{}`.
//
//	in                            out
//	{hash:"sha256:…"}             {digest:{sha256:…}}   ok
//	{name, hash:"sha256:…"}       {digest, name}        ok
//	{digest:{sha256:…}}           {}                    everything gone, silently
//	{name, digest:{…}}            {name}                the hash gone, silently
func TestSubjectMustNameSomething(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		subject  map[string]any
		accepted bool
	}{
		"digest identifies it":       {map[string]any{"digest": map[string]any{"sha256": hex64}}, true},
		"uri identifies it":          {map[string]any{"uri": "https://example.org/x"}, true},
		"named and digested":         {map[string]any{"name": "f.csv", "digest": map[string]any{"sha256": hex64}}, true},
		"empty names nothing":        {map[string]any{}, false},
		"a name is not an identity":  {map[string]any{"name": "f.csv"}, false},
		"an empty digest identifies": {map[string]any{"digest": map[string]any{}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			st, p := statementWith(t, tc.subject)
			err := st.Validate(p)
			if tc.accepted && err != nil {
				t.Fatalf("subject %v must be accepted, got %v", tc.subject, err)
			}
			if !tc.accepted && err == nil {
				t.Fatalf("subject %v names nothing and must be refused - it would sign, verify and "+
					"index, and no `about` query could ever reach it", tc.subject)
			}
		})
	}
}

// The cause, caught where a human writes the file: a field this build does not know is REFUSED,
// not dropped. A misspelling in a document that is about to be signed must never be an omission.
func TestParseSpecRefusesAnUnknownField(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for name, raw := range map[string]string{
		"digest instead of hash":      `{"subject":[{"digest":{"sha256":"` + hex64 + `"}}],"predicate":"https://kton.dev/v/note","by":"a","when":"2026-07-16T00:00:00Z"}`,
		"subjects instead of subject": `{"subjects":[{"hash":"sha256:` + hex64 + `"}],"predicate":"https://kton.dev/v/note","by":"a","when":"2026-07-16T00:00:00Z"}`,
		"a plain typo":                `{"subject":[{"hash":"sha256:` + hex64 + `"}],"predicat":"https://kton.dev/v/note","by":"a","when":"2026-07-16T00:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := claim.ParseSpec([]byte(raw)); err == nil {
				t.Fatal("an unknown field was accepted and silently dropped")
			}
		})
	}
	// And the shape that is actually correct still parses.
	ok := `{"subject":[{"name":"f.csv","hash":"sha256:` + hex64 + `"}],"predicate":"https://kton.dev/v/note","by":"a","when":"2026-07-16T00:00:00Z"}`
	if _, err := claim.ParseSpec([]byte(ok)); err != nil {
		t.Fatalf("the documented spec shape must parse: %v", err)
	}
}

// The `digest` message has to say what to write instead - it is the spelling a reader of the signed
// form reaches for, so "unknown field" alone sends them looking in the wrong place.
func TestTheDigestMistakeNamesItsFix(t *testing.T) {
	raw := `{"subject":[{"digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}],"predicate":"https://kton.dev/v/note","by":"a","when":"2026-07-16T00:00:00Z"}`
	_, err := claim.ParseSpec([]byte(raw))
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Error(), "`hash`") {
		t.Errorf("the error must name the field to use instead, got: %v", err)
	}
}
