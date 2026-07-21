package main

// fetch.go is the RESOLVER - the one place a URI is dereferenced. It belongs in kton and only
// in kton: plankton and nekton are strictly neutral, they CARRY a URI as an opaque signed
// string and never execute it (no git/http resolver in the kernels). A location is a signed
// nekton `located-at` claim (subject = content hash, object = uri); kton reads those claims,
// dereferences each suggested URI via a resolver backend that lives here, and verifies
// sha256(bytes) == hash before trusting a byte. Multiple claims = multiple signed suggestions.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
	"kton.dev/kton/federation"
	"kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
)

// LocatedAtTerm is the predicate IRI kton recognizes as "this content hash is retrievable at
// this URI" - the published DCAT term dcat:downloadURL, reused rather than minting our own
// (DECISIONS §20). It is a CONVENTION the cockpit knows; the kernels never interpret it.
const LocatedAtTerm = "http://www.w3.org/ns/dcat#downloadURL"

// fetch resolves a content hash to its bytes via signed located-at claims, verifies, and pins.
func fetch(hash string) error {
	hash = normalizeHash(hash)
	r, err := nreg.Open(nektonDir())
	if err != nil {
		return err
	}
	locs := locatedAt(r, hash)
	if len(locs) == 0 {
		return fmt.Errorf("no signed located-at claim for %s in %s (nothing suggests where it is)",
			hash, nektonDir())
	}
	fmt.Printf("%s: %d signed location(s) suggested\n", hash, len(locs))

	bs, err := blobstore.Open(filepath.Join(planktonDir(), federation.BlobsSubdir))
	if err != nil {
		return err
	}
	for i, l := range locs {
		fmt.Printf("  [%d] %s  (signed by %s) ... ", i+1, l.uri, l.by)
		b, err := deref(l.uri)
		if err != nil {
			fmt.Printf("unreachable: %v\n", err)
			continue
		}
		if got := core.HashBytes(b); got != hash {
			fmt.Printf("HASH MISMATCH (got %s) - rejected\n", got)
			continue
		}
		if err := bs.PutVerified(hash, b); err != nil {
			return err
		}
		fmt.Printf("OK - %d bytes, verified & pinned\n", len(b))
		return nil
	}
	return fmt.Errorf("no suggested location resolved to bytes matching %s", hash)
}

// normalizeHash canonicalizes a content-hash argument so equivalent spellings compare equal: trims
// surrounding whitespace, adds the implicit "sha256:" for a bare hex digest, and lowercases (hex is
// lowercase by convention). Without this, an authentic blob given as bare hex, UPPERCASE hex, or with a
// stray newline read as CORRUPT / MISMATCH / absent.
func normalizeHash(h string) string {
	h = strings.TrimSpace(h)
	if !strings.Contains(h, ":") {
		h = "sha256:" + h
	}
	return strings.ToLower(h)
}

type location struct{ uri, by string }

// locatedAt collects the signed location suggestions for `hash`: located-at claims whose
// subject is that hash. kton recognizes the located-at predicate as a convention and reads
// nothing else into it.
func locatedAt(r *nreg.Registry, hash string) []location {
	var out []location
	for _, rec := range r.About(hash) {
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(st.Predicate, &body); err != nil {
			continue
		}
		if predURI(body) != LocatedAtTerm {
			continue
		}
		obj, _ := body["object"].(map[string]any)
		uri, _ := obj["uri"].(string)
		if uri == "" {
			continue
		}
		by, _ := body["by"].(string)
		out = append(out, location{uri: uri, by: by})
	}
	return out
}

func predURI(body map[string]any) string {
	if p, ok := body["predicate"].(map[string]any); ok {
		if u, ok := p["uri"].(string); ok {
			return u
		}
	}
	return ""
}

// deref dereferences a URI to bytes. Resolver backends live ONLY here in the cockpit; http(s)
// and file today, git/ipfs are future kton backends. The kernels never do this.
func deref(uri string) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		c := &http.Client{Timeout: 120 * time.Second}
		resp, err := c.Get(uri)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	case strings.HasPrefix(uri, "file://"):
		return os.ReadFile(strings.TrimPrefix(uri, "file://"))
	default:
		return nil, fmt.Errorf("no kton resolver for the scheme of %q", uri)
	}
}
