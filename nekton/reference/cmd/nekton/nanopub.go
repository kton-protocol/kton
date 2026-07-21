package main

// nanopub.go renders a signed nekton claim to its INTEROP FACE: a nanopublication (RDF/TriG,
// four named graphs - Head, assertion, provenance, pubinfo). Per docs/nekton-as-nanopub-profile.md
// a nekton statement IS a nanopublication; TriG is a rendering of the same inert claim, not a new
// storage form. The claim stays DSSE-signed on disk; this is the network face for reuse.
//
// The mapping (doc's table): subject-by-hash -> assertion subject (pk:<hash>); predicate -> the
// resolved IRI; the multi-field object bag -> a blank node with one property per field, each field
// key resolved to an IRI via the vocab/aliases; by/when/context -> provenance; the DSSE signature
// + the seedchain (scope/prev/genesis) -> pubinfo.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// loadTrustKeys reads every *.pub (raw hex Ed25519) under dir - the verifier's trusted key set. Export
// attribution is derived from which of THESE keys actually signed a claim, not its self-declared keyid.
func loadTrustKeys(dir string) ([]ed25519.PublicKey, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		pub, err := core.ParsePublicKeyHex(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("trust-keys: %s: %w", e.Name(), err)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

// defaultPrefixes are the nanopublication + provenance vocab prefixes; merged with (and overridden
// by) whatever the aliases file declares.
var defaultPrefixes = map[string]string{
	"np":    "http://www.nanopub.org/nschema#",
	"npx":   "http://purl.org/nanopub/x/",
	"prov":  "http://www.w3.org/ns/prov#",
	"pav":   "http://purl.org/pav/",
	"dct":   "http://purl.org/dc/terms/",
	"xsd":   "http://www.w3.org/2001/XMLSchema#",
	"rdfs":  "http://www.w3.org/2000/01/rdf-schema#",
	"nk":    "https://kton.dev/v/",
	"pk":    "https://kton.dev/o/",
	"agent": "https://kton.dev/agent/",
}

type trigCtx struct {
	prefixes  map[string]string // prefix -> IRI namespace
	revExp    []struct{ pfx, ns string }
	fieldNS   string // default namespace for unresolved object-field keys
	al        aliasFile
	trustKeys []ed25519.PublicKey // verifier's trusted keys; attribution is derived from these, not the claimed keyid
}

func newTrigCtx(al aliasFile) *trigCtx {
	pfx := map[string]string{}
	for k, v := range defaultPrefixes {
		pfx[k] = v
	}
	for k, v := range al.Prefixes {
		pfx[k] = v
	}
	c := &trigCtx{prefixes: pfx, fieldNS: pfx["lab"], al: al}
	if c.fieldNS == "" {
		c.fieldNS = "https://kton.dev/v/lab/"
	}
	for k, v := range pfx {
		c.revExp = append(c.revExp, struct{ pfx, ns string }{k, v})
	}
	sort.Slice(c.revExp, func(i, j int) bool { return len(c.revExp[i].ns) > len(c.revExp[j].ns) })
	return c
}

// iriEsc percent-encodes the characters a Turtle/TriG IRIREF forbids ( <>"{}|^`\ and controls/space,
// per the grammar). WITHOUT this, an attacker-controlled object value like `http://x> . sub:o
// prov:wasAttributedTo <agent/CEO-BOARD` - which reaches the IRI path because it contains "://" - would
// close the <...> early and INJECT triples into the SIGNED assertion graph (the rendering face != the
// signed content; cold-session RDF-injection RED). Escaping keeps the value one inert IRI.
func iriEsc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ { // iterate BYTES: forbidden chars are all ASCII; UTF-8 tails (>=0x80) pass
		if ch := s[i]; ch <= 0x20 || strings.IndexByte("<>\"{}|^`\\", ch) >= 0 {
			fmt.Fprintf(&b, "%%%02X", ch)
		} else {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// safePNLocal reports whether local is safe to emit UNESCAPED as a prefixed-name local part - a
// conservative PN_LOCAL subset. Anything else falls back to an escaped full IRI, so a crafted value
// can never break out of the term.
func safePNLocal(local string) bool {
	if local == "" {
		return false
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// curie shortens a full IRI to prefix:local when a known namespace matches; else an ESCAPED <IRI>.
func (c *trigCtx) curie(iri string) string {
	for _, e := range c.revExp {
		if strings.HasPrefix(iri, e.ns) && len(iri) > len(e.ns) {
			local := iri[len(e.ns):]
			// Only emit an unescaped prefixed name for a safe local part; else fall back to an escaped
			// full IRI (a Turtle parser rejects e.g. `nk:lab/value`, and a crafted local must not inject).
			if safePNLocal(local) {
				return e.pfx + ":" + local
			}
			return "<" + iriEsc(iri) + ">"
		}
	}
	return "<" + iriEsc(iri) + ">"
}

// fieldIRI resolves an object-field key (e.g. "outcome") to a term IRI, via the aliases if it is a
// known term/CURIE, else minting it in the default lab namespace.
func (c *trigCtx) fieldIRI(key string) string {
	if r := c.al.resolve(key); strings.Contains(r, "://") {
		return c.curie(r)
	}
	return c.curie(c.fieldNS + key)
}

// hashRef renders a "sha256:<hex>" value as pk:<hex>; a URI as its curie; anything else as a literal.
func (c *trigCtx) hashRef(v string) string {
	if strings.HasPrefix(v, "sha256:") {
		return c.curie(c.prefixes["pk"] + strings.TrimPrefix(v, "sha256:"))
	}
	if strings.Contains(v, "://") {
		return c.curie(v)
	}
	return quote(v)
}

func quote(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\t", "\\t")
	return "\"" + r.Replace(s) + "\""
}

func agentIRI(c *trigCtx, by string) string {
	if strings.Contains(by, "://") {
		return c.curie(by)
	}
	return c.curie(c.prefixes["agent"] + core.HashBytes([]byte(by))[7:19]) // stable slug from `by`
}

// exportNanopub renders one signed claim envelope to nanopublication TriG.
func exportNanopub(args []string) error {
	var in, out, creator, trustDir string
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			i++
			out = arg(args, i)
		case "--trust-keys":
			i++
			trustDir = arg(args, i)
		case "--creator":
			// The IRI (e.g. an ORCID) that publishes this nanopub - becomes pav:createdBy in
			// pubinfo. Set it to the signer so signer == creator; the assertion's ORIGINAL author
			// stays in provenance (prov:wasAttributedTo). A publish-edge concern (kton nanopublish).
			i++
			creator = arg(args, i)
		case "--aliases":
			i++
			aliasesPath = arg(args, i)
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			in = args[i]
		}
	}
	if in == "" {
		return fmt.Errorf("usage: nekton export --nanopub <claim.dsse.json|sha256:id> [-o out.trig] [--aliases file]")
	}
	env, err := readEnvelopeOrID(in)
	if err != nil {
		return err
	}
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal(st.Predicate, &body); err != nil {
		return err
	}
	id := strings.TrimPrefix(claim.ClaimID(payload), "sha256:")
	c := newTrigCtx(loadAliases(aliasesPath))
	if trustDir != "" {
		ks, err := loadTrustKeys(trustDir)
		if err != nil {
			return err
		}
		c.trustKeys = ks
	}
	trig := renderTrig(c, st, body, env, id, creator, "", "")
	if out == "" || out == "-" {
		fmt.Print(trig)
		return nil
	}
	return os.WriteFile(out, []byte(trig), 0o644)
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func uriOf(m map[string]any, k string) string {
	if o, ok := m[k].(map[string]any); ok {
		if u, ok := o["uri"].(string); ok {
			return u
		}
	}
	return ""
}

// renderTrig serializes a claim to nanopublication TriG. baseOverride, when non-empty, replaces the
// default (pre-Trusty) base URI - `nekton nanopublish` passes the minted Trusty URI. extraPubinfo, when
// non-empty, is injected into the pubinfo graph (the npx: signature block).
func renderTrig(c *trigCtx, st *claim.Statement, body map[string]any, env core.Envelope, id, creator, baseOverride, extraPubinfo string) string {
	var b strings.Builder
	base := "https://kton.dev/np/" + id + "."
	if baseOverride != "" {
		base = baseOverride
	}
	// prefixes
	keys := make([]string, 0, len(c.prefixes))
	for k := range c.prefixes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "@prefix %s: <%s> .\n", k, c.prefixes[k])
	}
	b.WriteString("# pre-Trusty: this np id stands in for the not-yet-minted Trusty URI (it equals the source\n# claim id here) - do NOT read that coincidence as hash equality; the binding is prov:wasDerivedFrom (spec §14).\n")
	fmt.Fprintf(&b, "@prefix this: <%s> .\n@prefix sub: <%s#> .\n\n", base, base)

	// Head
	b.WriteString("sub:Head {\n  this: a np:Nanopublication ;\n    np:hasAssertion sub:assertion ;\n    np:hasProvenance sub:provenance ;\n    np:hasPublicationInfo sub:pubinfo .\n}\n\n")

	by, when := str(body, "by"), str(body, "when")
	agent := agentIRI(c, by)
	signerVerified := false
	if len(env.Signatures) > 0 {
		// Attribute to the CRYPTOGRAPHICALLY-VERIFIED signer (the trusted key that actually signed this
		// claim), never the self-declared keyid a relabeler can forge. Without a trusted key that
		// verifies it, the attribution is marked UNVERIFIED below (nk:claimedSigner, not
		// prov:wasAttributedTo), so a gate/consumer never reads a forged signer as established.
		if vk := core.VerifiedSignerKeyID(env, c.trustKeys); vk != "" {
			agent = c.curie(c.prefixes["agent"] + vk)
			signerVerified = true
		} else {
			agent = c.curie(c.prefixes["agent"] + env.Signatures[0].KeyID)
		}
	}

	// Assertion
	b.WriteString("sub:assertion {\n")
	if st.PredicateType == claim.ScopePredicateType {
		// a seed: the scope comes into being
		scope := str(body, "scope")
		fmt.Fprintf(&b, "  <urn:nekton:scope:%s> a nk:Scope ;\n    rdfs:label %s .\n", scope, quote(scope))
	} else {
		subj := "<urn:nekton:claim>"
		if len(st.Subject) > 0 {
			subj = c.hashRef(st.Subject[0].Key())
		}
		// Expand a raw CURIE predicate (e.g. a bare `nekton claim` stored "gxp:reviewed") to its full
		// IRI first, so curie() re-renders it as a DECLARED prefixed name (or the full IRI) - not a bare
		// <gxp:reviewed>, which a prefixed SPARQL query silently never matches.
		pred := c.curie(c.expand(uriOf(body, "predicate")))
		fmt.Fprintf(&b, "  %s %s sub:o .\n", subj, pred)
		// object field bag -> blank-node properties
		var lines []string
		if obj, ok := body["object"].(map[string]any); ok {
			fkeys := make([]string, 0, len(obj))
			for k := range obj {
				fkeys = append(fkeys, k)
			}
			sort.Strings(fkeys)
			for _, k := range fkeys {
				lines = append(lines, fmt.Sprintf("    %s %s", c.fieldIRI(k), c.hashRef(fmt.Sprintf("%v", obj[k]))))
			}
		}
		if ev, ok := body["evidence"].([]any); ok {
			for _, e := range ev {
				if em, ok := e.(map[string]any); ok {
					if h, ok := em["hash"].(string); ok {
						lines = append(lines, fmt.Sprintf("    nk:evidence %s", c.hashRef(h)))
					}
				}
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "  sub:o\n%s .\n", strings.Join(lines, " ;\n"))
		}
	}
	b.WriteString("}\n\n")

	// Provenance
	b.WriteString("sub:provenance {\n  sub:assertion")
	if signerVerified {
		fmt.Fprintf(&b, "\n    prov:wasAttributedTo %s ;\n    nk:signerVerified true", agent)
	} else {
		// no trusted key verified this signature: carry the CLAIMED signer, but do not assert it as
		// established attribution (a consumer/gate that trusts prov:wasAttributedTo must not see it here).
		fmt.Fprintf(&b, "\n    nk:claimedSigner %s ;\n    nk:signerVerified false", agent)
	}
	if when != "" {
		fmt.Fprintf(&b, " ;\n    prov:generatedAtTime %s^^xsd:dateTime", quote(when))
	}
	if ctx := uriOf(body, "context"); ctx != "" {
		fmt.Fprintf(&b, " ;\n    dct:subject %s", c.curie(ctx))
	}
	b.WriteString(" .\n")
	if ev, ok := body["evidence"].([]any); ok {
		for _, e := range ev {
			if em, ok := e.(map[string]any); ok {
				h, _ := em["hash"].(string)
				mt, _ := em["mediaType"].(string)
				if h != "" && mt != "" {
					fmt.Fprintf(&b, "  %s dct:format %s .\n", c.hashRef(h), quote(mt))
				}
			}
		}
	}
	b.WriteString("}\n\n")

	// Publication info (incl. the seedchain profile + the DSSE signature). prov:wasDerivedFrom is
	// always present, so it anchors the property list; createdBy/creator are added ONLY when we actually
	// know the publisher - an explicit creator IRI, or a CRYPTOGRAPHICALLY-VERIFIED signer. An unverified
	// (e.g. relabelled) signer must NOT be stamped as pav:createdBy/dct:creator: that reads as an
	// established publisher identity, the same forgeable-attribution hole verified-attribution closed in
	// the provenance graph (the claimed signer is still carried, unverified, as nk:claimedSigner above).
	b.WriteString("sub:pubinfo {\n  this:")
	// Explicit back-reference to the source nekton claim, by content hash. `this:` currently encodes the
	// claim id in its base URI, but a network-verifiable nanopub replaces `this:` with a Trusty URI
	// (hash of the normalized RDF), which would drop that implicit link. Stating it explicitly keeps the
	// durable projection bound to the authoritative claim it is a projection of - the provenance join
	// between the ephemeral (DSSE/Sigstore) and permanent (RSA nanopub) records.
	fmt.Fprintf(&b, "\n    prov:wasDerivedFrom %s", c.hashRef("sha256:"+id))
	if creator != "" {
		cb := c.curie(creator)
		fmt.Fprintf(&b, " ;\n    pav:createdBy %s ;\n    dct:creator %s", cb, cb)
	} else if signerVerified {
		fmt.Fprintf(&b, " ;\n    pav:createdBy %s ;\n    dct:creator %s", agent, agent)
	}
	if when != "" {
		fmt.Fprintf(&b, " ;\n    dct:created %s^^xsd:dateTime", quote(when))
	}
	if g, _ := body["genesis"].(bool); g {
		fmt.Fprintf(&b, " ;\n    nk:genesis true ;\n    nk:scope %s", c.hashRef("sha256:"+id))
	} else {
		if sc := str(body, "scope"); sc != "" {
			fmt.Fprintf(&b, " ;\n    nk:scope %s", c.hashRef(sc))
		}
		if pv := str(body, "prev"); pv != "" {
			fmt.Fprintf(&b, " ;\n    nk:prev %s", c.hashRef(pv))
		}
	}
	fmt.Fprintf(&b, " ;\n    rdfs:label %s .\n", quote(by))
	fmt.Fprintf(&b, "  %s rdfs:label %s .\n", agent, quote(by))
	if len(env.Signatures) > 0 {
		// The authoritative signature is DSSE/Ed25519 over the in-toto Statement (verify via
		// `nekton verify`), NOT a nanopublication-native RSA signature over the normalized RDF.
		// So we carry it as nekton provenance - NOT as npx:hasSignature, which would falsely assert
		// a nanopub-verifiable signature (wrong algorithm AND wrong signed bytes). Identity here is
		// the content address (this:). A network-verifiable nanopub must RE-SIGN over the canonical
		// RDF at this export edge (RSA, per the npx convention); that step is deferred.
		fmt.Fprintf(&b, "  this:\n    nk:signedAs \"in-toto/DSSE\" ;\n    nk:signatureAlgorithm \"ed25519\" ;\n    nk:keyid %s ;\n    nk:dsseSignature %s .\n",
			quote(env.Signatures[0].KeyID), quote(env.Signatures[0].Sig))
	}
	if extraPubinfo != "" {
		b.WriteString(extraPubinfo)
	}
	b.WriteString("}\n")
	return b.String()
}
