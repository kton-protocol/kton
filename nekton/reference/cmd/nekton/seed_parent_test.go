package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

// `seed --parent <hash>` emitted the SUBJECT shape, {"digest":{"sha256":...}}, while claim.Ref reads
// {hash?, uri?} (nekton SPEC §7.4: `parent?: Ref`). The scope hierarchy an operator asked for was
// therefore SIGNED in a representation the library's own parser could not interpret: the round-trip
// produced an empty Hash and an empty Parent.Key() (dev review R11).
//
// The assertion is the round trip through the PUBLIC parser, not the shape of the JSON: a test that
// only checked for the string "hash" would pass on output nothing can read.
func TestSeedParentRoundTripsThroughThePublicParser(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NEKTON_DIR", filepath.Join(dir, "reg"))
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("3c", 32)}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k.key")
	parent := "sha256:" + strings.Repeat("a", 64)

	parsedParent := func(t *testing.T, path string) claim.Ref {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var st struct {
			Predicate struct {
				Parent claim.Ref `json:"parent"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		return st.Predicate.Parent
	}

	t.Run("a content-hash parent survives the round trip", func(t *testing.T) {
		out := filepath.Join(dir, "child.dsse.json")
		if err := seed([]string{"lab/child", "--parent", parent, "--sign", key,
			"--when", "2026-07-16T00:00:00Z", "-o", out}); err != nil {
			t.Fatal(err)
		}
		got := parsedParent(t, out)
		if got.Hash != parent {
			t.Errorf("parsed parent hash = %q, want %q - the signed parent is unreadable", got.Hash, parent)
		}
		if got.Key() != parent {
			t.Errorf("parsed parent key = %q, want %q", got.Key(), parent)
		}
	})

	t.Run("a URI parent survives the round trip", func(t *testing.T) {
		out := filepath.Join(dir, "uri.dsse.json")
		uri := "https://example.org/scope/a"
		if err := seed([]string{"lab/uri", "--parent", uri, "--sign", key,
			"--when", "2026-07-16T00:00:00Z", "-o", out}); err != nil {
			t.Fatal(err)
		}
		if got := parsedParent(t, out); got.URI != uri || got.Key() != uri {
			t.Errorf("parsed parent = %+v, want uri %q", got, uri)
		}
	})

	// A parent that is neither must be refused at authoring rather than signed into a permanent id.
	t.Run("a malformed parent is refused", func(t *testing.T) {
		for _, bad := range []string{"not-a-hash", "sha256:" + strings.Repeat("a", 63), "sha256:zzz"} {
			out := filepath.Join(dir, "bad.dsse.json")
			if err := seed([]string{"lab/bad", "--parent", bad, "--sign", key,
				"--when", "2026-07-16T00:00:00Z", "-o", out}); err == nil {
				t.Errorf("seed --parent %q was accepted", bad)
			}
		}
	})
}
