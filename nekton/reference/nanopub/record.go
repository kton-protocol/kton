package nanopub

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// The per-record projection (#232), the nekton half of kton.dev/plankton/rdf's Record/Attribution:
// for an index that stores each claim once and decides trust at query time.
//
// RenderTrig and Quads decide attribution from the context's trusted keys, so the same claim projects
// differently - and gets a different Trusty URI - under different keys. Here the two parts are apart:
//
//   - Record is the claim's own nanopublication quads (head, assertion, provenance, pubinfo), with
//     everything that depends on a key or on the envelope's signatures taken out: no
//     prov:wasAttributedTo, no nk:signerVerified, no nk:claimedSigner, no pav:createdBy/dct:creator,
//     no label on the claimed agent, no DSSE keyid or signature, no RSA signature element (that is
//     nanopublish's). A function of the signed claim alone, the same bytes on every machine.
//   - Attribution is one named graph per given key that verifies the claim's envelope, holding what
//     Record left out for that key.
//
// No attribution graph means unverified. Output is canonical N-Quads.

const attributionNS = "https://kton.dev/attribution/"

// RecordBase is the base IRI of a claim's own graphs (<base>#Head, #assertion, #provenance, #pubinfo),
// the same base RenderTrig uses.
func RecordBase(claimID string) string {
	return "https://kton.dev/np/" + strings.TrimPrefix(claimID, "sha256:") + "."
}

// AttributionGraph is the named graph that holds the attribution of a claim to one key.
func AttributionGraph(claimID, keyid string) string {
	return attributionNS + strings.TrimPrefix(claimID, "sha256:") + "/" + keyid
}

func parseRecord(env core.Envelope) (*claim.Statement, map[string]any, string, error) {
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return nil, nil, "", err
	}
	var body map[string]any
	if err := json.Unmarshal(st.Predicate, &body); err != nil {
		return nil, nil, "", fmt.Errorf("claim predicate: %w", err)
	}
	return st, body, strings.TrimPrefix(claim.ClaimID(payload), "sha256:"), nil
}

// Record returns the claim's own quads as canonical N-Quads.
func Record(c *Context, env core.Envelope) ([]byte, error) {
	st, body, id, err := parseRecord(env)
	if err != nil {
		return nil, err
	}
	keyless := *c
	keyless.trustKeys = nil
	P := c.prefixes
	sig := npTempBase + "#sig"
	drop := map[string]bool{
		P["prov"] + "wasAttributedTo": true, P["nk"] + "signerVerified": true, P["nk"] + "claimedSigner": true,
		P["pav"] + "createdBy": true, P["dct"] + "creator": true,
		P["nk"] + "keyid": true, P["nk"] + "dsseSignature": true,
	}
	base := RecordBase(id)
	rebase := func(iri string) string {
		if strings.HasPrefix(iri, npTempBase) {
			return base + iri[len(npTempBase):]
		}
		return iri
	}
	var own []npQuad
	for _, q := range nanopubQuads(&keyless, st, body, env, id, "", "", "") {
		if drop[q.p] || q.s == sig || (strings.HasPrefix(q.s, P["agent"]) && q.p == P["rdfs"]+"label") {
			continue
		}
		q.s, q.p, q.g = rebase(q.s), rebase(q.p), rebase(q.g)
		if !q.o.isLit {
			q.o.iri = rebase(q.o.iri)
		}
		own = append(own, q)
	}
	return canonicalize(own), nil
}

// Attribution returns, for every key in keys that verifies the claim's envelope, that key's
// attribution as canonical N-Quads in graph AttributionGraph(claimID, keyid). A key listed twice is
// one entry.
func Attribution(c *Context, env core.Envelope, keys []ed25519.PublicKey) (map[string][]byte, error) {
	_, body, id, err := parseRecord(env)
	if err != nil {
		return nil, err
	}
	P := c.prefixes
	base := RecordBase(id)
	assertion, np := base+"#assertion", base
	by := str(body, "by")
	out := map[string][]byte{}
	for _, pub := range keys {
		if ok, err := env.Verify(pub); !ok || err != nil {
			continue
		}
		kid := core.KeyIDHex(pub)
		agent, g := P["agent"]+kid, AttributionGraph(id, kid)
		qs := []npQuad{
			{assertion, P["prov"] + "wasAttributedTo", g, iriT(agent)},
			{assertion, P["nk"] + "signerVerified", g, litT("true", P["xsd"]+"boolean")},
			{np, P["pav"] + "createdBy", g, iriT(agent)},
			{np, P["dct"] + "creator", g, iriT(agent)},
		}
		if by != "" {
			qs = append(qs, npQuad{agent, P["rdfs"] + "label", g, litT(by, "")})
		}
		out[kid] = canonicalize(qs)
	}
	return out, nil
}
