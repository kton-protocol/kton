package nanopub

import (
	"testing"

	"kton.dev/nekton/template"
)

// An alias set may declare a second prefix for a namespace the projection already knows. Which one an
// IRI gets must not depend on map order: the name decides, every time.
func TestPrefixTieIsDecidedByName(t *testing.T) {
	al, err := template.New(nil, []byte(`{"prefixes":{"dcterms":"http://purl.org/dc/terms/","zz":"http://purl.org/dc/terms/"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if got := newTrigCtx(al).curie("http://purl.org/dc/terms/title"); got != "dct:title" {
			t.Fatalf("run %d: got %s, want dct:title", i, got)
		}
	}
}
