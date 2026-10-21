package nanopub

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/template"
	"kton.dev/plankton/core"
)

// The per-record projection (#232), the nekton half of kton.dev/plankton/rdf's Record/Attribution:
// for an index that stores each claim once and decides trust at query time.
//
// RenderTrig and Quads decide attribution from the context's trusted keys, so the same claim projects
// differently - and gets a different Trusty URI - under different keys. Here the two parts are apart:
//
//   - Record is the claim's own nanopublication quads, with everything that depends on a key or on
//     the envelope's signatures taken out: no prov:wasAttributedTo, no nk:signerVerified, no
//     nk:claimedSigner, no pav:createdBy/dct:creator, no label on the claimed agent, no DSSE keyid or
//     signature, no RSA signature element (that is nanopublish's). It ignores the context's trusted
//     keys; NewRecordContext builds a context without any. A function of the signed claim alone, the
//     same bytes on every machine.
//   - Attribution is one named graph per given key that verifies the claim's envelope, holding what
//     Record left out for that key.
//
// Contract: every own quad is in one of the claim's four graphs - RecordBase(id) + "#Head",
// "#assertion", "#provenance", "#pubinfo" - and none is in the default graph. No attribution graph
// means unverified. Output is canonical N-Quads.
//
// The own quads use a stricter term rule than nanopublish (whose quads feed the Trusty URI and
// therefore keep their historical form): a value becomes an IRI only if it is a valid content hash or
// a valid absolute IRI, else a literal; every control character in a literal is escaped; and a claim
// that would still yield an invalid IRI (its predicate, its subject) is refused rather than emitted
// as a document a parser rejects.

const attributionNS = "https://kton.dev/attribution/"

// NewRecordContext returns a context for Record and Attribution: the alias set's prefixes, and no
// trusted keys - Record's output must not depend on any.
func NewRecordContext(al template.Set) *Context { return NewContext(al, nil) }

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
	// An unsigned envelope is not a record (the registry refuses it), and its quads would differ from
	// the signed one's: refused here as there.
	if !env.HasSignature() {
		return nil, nil, "", fmt.Errorf("an unsigned envelope is not a record")
	}
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
	keyless.strict = true
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
	return recordNQuads(own)
}

// Records returns the own quads of several claims as one canonical N-Quads document, for a cold
// rebuild of an index.
func Records(c *Context, envs []core.Envelope) ([]byte, error) {
	var all []string
	for _, env := range envs {
		b, err := Record(c, env)
		if err != nil {
			return nil, err
		}
		all = append(all, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")...)
	}
	return joinSorted(all), nil
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
		b, err := recordNQuads(qs)
		if err != nil {
			return nil, err
		}
		out[kid] = b
	}
	return out, nil
}

var iriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)

// strictIRI reports whether s can stand as an absolute IRI in N-Quads as it is: a scheme, and none of
// the characters the grammar forbids (controls, space, <>"{}|^`\), nor the C1 controls or the
// Unicode line and paragraph separators, which parsers reject in practice.
func strictIRI(s string) bool {
	if !iriScheme.MatchString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || strings.ContainsRune("<>\"{}|^`\\", r) {
			return false
		}
	}
	return true
}

// recordNQuads serializes quads as canonical N-Quads under the strict rule: an IRI that cannot stand
// is an error, and a literal escapes every control character.
func recordNQuads(qs []npQuad) ([]byte, error) {
	// Characters an IRI may not carry are percent-encoded, as the TriG face does, plus the C1 controls
	// and U+2028/U+2029, which parsers reject. What is left to refuse is an IRI with no scheme.
	iri := func(s string) (string, error) {
		e := recordIRIEsc(s)
		if !strictIRI(e) {
			return "", fmt.Errorf("%q is not an absolute IRI, so this claim has no well-formed per-record projection", s)
		}
		return "<" + e + ">", nil
	}
	lines := make([]string, 0, len(qs))
	for _, q := range qs {
		s, err := iri(q.s)
		if err != nil {
			return nil, err
		}
		p, err := iri(q.p)
		if err != nil {
			return nil, err
		}
		g, err := iri(q.g)
		if err != nil {
			return nil, err
		}
		var o string
		if q.o.isLit {
			o = nqLiteral(q.o.lit)
			if q.o.dt != "" && q.o.dt != xsdString {
				dt, err := iri(q.o.dt)
				if err != nil {
					return nil, err
				}
				o += "^^" + dt
			}
		} else if o, err = iri(q.o.iri); err != nil {
			return nil, err
		}
		lines = append(lines, s+" "+p+" "+o+" "+g+" .")
	}
	return joinSorted(lines), nil
}

// recordIRIEsc percent-encodes, as UTF-8 bytes, every character strictIRI refuses.
func recordIRIEsc(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r <= 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || strings.ContainsRune("<>\"{}|^`\\", r) {
			for _, c := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", c)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func joinSorted(lines []string) []byte {
	sort.Strings(lines)
	var b strings.Builder
	for i, l := range lines {
		if l == "" || (i > 0 && l == lines[i-1]) {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// nqLiteral renders s as an N-Quads string literal: the named escapes, and every other control
// character as \uXXXX.
func nqLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
