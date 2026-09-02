package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nclaim "kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
)

// SPEC §12 lists claim?id= in the minimum nekton federation surface, and §15 item 4 makes indexing
// and resolving per Clauses 11-12 a conformance requirement. There was no /claim route at all: a
// peer holding an id from a chain's `prev` had no way to ask for exactly that record.
//
// The other half matters as much. /claims had no default case, so a misspelled parameter fell
// through and returned {"records":[]} - a SUCCESSFUL wrong answer, indistinguishable from "that
// subject has no claims". That is what would have kept the missing route from being noticed.
func TestFederationClaimSurface(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NEKTON_DIR", dir)
	id := seedOneClaim(t, dir)

	srv := httptest.NewServer(nektonServer(dir))
	defer srv.Close()

	get := func(path string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	t.Run("claim by id", func(t *testing.T) {
		code, body := get("/claim?id=" + id)
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200", code)
		}
		recs, _ := body["records"].([]any)
		if len(recs) != 1 {
			t.Errorf("records = %d, want exactly the one asked for", len(recs))
		}
	})

	t.Run("an uppercase or bare digest still resolves", func(t *testing.T) {
		for _, form := range []string{strings.ToUpper(id), strings.TrimPrefix(id, "sha256:")} {
			if code, _ := get("/claim?id=" + form); code != http.StatusOK {
				t.Errorf("%q: status %d - SPEC §5.1 requires it resolve under the stored key", form, code)
			}
		}
	})

	t.Run("absent is 404, not an empty list", func(t *testing.T) {
		// "this registry does not hold it" and "it holds nothing about it" are different answers,
		// and a federated reader acts differently on each.
		if code, _ := get("/claim?id=sha256:" + strings.Repeat("f", 64)); code != http.StatusNotFound {
			t.Errorf("status %d, want 404", code)
		}
		if code, _ := get("/claim"); code != http.StatusBadRequest {
			t.Errorf("no id: status %d, want 400", code)
		}
	})

	t.Run("a misspelled claims parameter is refused, not answered emptily", func(t *testing.T) {
		if code, _ := get("/claims?subjekt=" + id); code != http.StatusBadRequest {
			t.Errorf("status %d, want 400 - an empty 200 here is a successful wrong answer", code)
		}
		if code, body := get("/claims?subject=" + id); code != http.StatusOK || body["records"] == nil {
			t.Errorf("the working form broke: status %d, body %v", code, body)
		}
	})
}

func seedOneClaim(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, id, err := nclaim.SignWith(nclaim.Spec{
		Subject:   []nclaim.SubjectSpec{{URI: "urn:demo:x"}},
		Predicate: "https://kton.dev/v/note",
		By:        "key:test", When: "2026-07-16T00:00:00Z",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nreg.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	return id
}
