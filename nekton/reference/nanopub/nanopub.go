package nanopub

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

// The library face of the nanopublication projection (proposal K8). It used to live in package main
// of cmd/nekton, so only the CLI could render a claim as RDF; a linking caller (a cockpit feeding a
// SPARQL engine) had to shell out or write a second mapping - and two mappings are two opinions
// about what a claim says in RDF.

// Context carries the prefixes, the alias set and the verifier's trusted keys for rendering.
type Context = trigCtx

// NewContext returns a rendering context. trustKeys decide attribution: a claim is attributed
// (prov:wasAttributedTo) only to a trusted key that verifies it.
func NewContext(al template.Set, trustKeys []ed25519.PublicKey) *Context {
	c := newTrigCtx(al)
	c.trustKeys = trustKeys
	return c
}

// RenderTrig renders one claim as nanopublication TriG (see renderTrig).
func RenderTrig(c *Context, st *claim.Statement, body map[string]any, env core.Envelope, id, creator, baseOverride, extraPubinfo string) string {
	return renderTrig(c, st, body, env, id, creator, baseOverride, extraPubinfo)
}

// Quad is one RDF quad of a nanopublication.
type Quad = npQuad

// Quads builds the quads of a nanopublication (see nanopubQuads).
func Quads(c *Context, st *claim.Statement, body map[string]any, env core.Envelope, id, creator, pubB64, sig string) []Quad {
	return nanopubQuads(c, st, body, env, id, creator, pubB64, sig)
}

// Canonicalize, QuadsToTrig and TrustyURI are the signing and minting steps of nanopublish.
func Canonicalize(qs []Quad) []byte                         { return canonicalize(qs) }
func QuadsToTrig(c *Context, qs []Quad, base string) string { return quadsToTrig(c, qs, base) }
func TrustyURI(canon []byte) string                         { return trustyURI(canon) }

// SetTrustKeys replaces the verifier's trusted keys of a context.
func (c *trigCtx) SetTrustKeys(keys []ed25519.PublicKey) { c.trustKeys = keys }

// URIOf reads m[k].uri, the form a claim body gives its predicate and context.
func URIOf(m map[string]any, k string) string { return uriOf(m, k) }

// Registry renders every claim a registry holds as nanopublications, one after another in a single
// TriG document - the form a triple store loads in one go. Each nanopublication keeps its own base
// (this:/sub: are re-declared per claim, which TriG permits), so the named graphs never collide.
// A record that is not a parseable claim is skipped, never guessed at.
func Registry(reg *registry.Registry, c *Context) (string, int) {
	var b strings.Builder
	n := 0
	for _, rec := range reg.Records(0) {
		st, payload, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		var body map[string]any
		if json.Unmarshal(st.Predicate, &body) != nil {
			continue
		}
		id := strings.TrimPrefix(claim.ClaimID(payload), "sha256:")
		b.WriteString(renderTrig(c, st, body, rec.Envelope, id, "", "", ""))
		b.WriteString("\n")
		n++
	}
	return b.String(), n
}
