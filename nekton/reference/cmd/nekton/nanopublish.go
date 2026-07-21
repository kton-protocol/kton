package main

// nanopublish.go turns a signed nekton claim into a REAL nanopublication: it re-signs the normalized
// RDF with RSA (the npx convention), mints a Trusty URI (a content hash baked into the nanopub's own
// name), and keeps the DSSE<->RSA provenance join so the same statement is verifiable in both worlds.
//
// The crux is canonicalization. A nanopub's Trusty URI and its RSA signature are computed over a
// deterministic serialization of the RDF, with the nanopub's own (not-yet-known) base URI replaced by a
// placeholder - so the name can be a hash of the content that names it. Our nanopubs have NO true blank
// nodes (`sub:o` is a base-relative named node), so canonicalization is: expand to full-IRI N-Quads,
// blank the self-base, sort, hash. This follows the nanopub npx SHAPE and the Trusty-URI RA convention
// (RA + base64url(SHA-256)); byte-exact interop with the ecosystem's trustyuri normalizer (its exact
// escaping and blank-node handling) is a calibration step, flagged where it bites.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

const (
	rdfType    = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	xsdString  = "http://www.w3.org/2001/XMLSchema#string"
	npTempBase = "https://kton.dev/np/TEMP." // stand-in self-base during signing; hashed as a placeholder
	npSelfMark = "@@SELF"                    // what the self-base collapses to before hashing
)

// npTerm is an RDF term: a full IRI, or a literal with an optional datatype.
type npTerm struct {
	iri, lit, dt string
	isLit        bool
}
type npQuad struct {
	s, p, g string // IRIs
	o       npTerm
}

func iriT(iri string) npTerm   { return npTerm{iri: iri} }
func litT(v, dt string) npTerm { return npTerm{lit: v, dt: dt, isLit: true} }

// expand turns a curie ("pfx:local") or "<IRI>" into a bare full IRI.
func (c *trigCtx) expand(cur string) string {
	if strings.HasPrefix(cur, "<") {
		return strings.TrimSuffix(strings.TrimPrefix(cur, "<"), ">")
	}
	if i := strings.IndexByte(cur, ':'); i >= 0 {
		if ns, ok := c.prefixes[cur[:i]]; ok {
			return ns + cur[i+1:]
		}
	}
	return cur
}

// refTerm mirrors hashRef but returns a typed term (for N-Quads): sha256 -> pk: IRI, a URI -> IRI,
// else a plain-string literal.
func (c *trigCtx) refTerm(v string) npTerm {
	if strings.HasPrefix(v, "sha256:") {
		return iriT(c.prefixes["pk"] + strings.TrimPrefix(v, "sha256:"))
	}
	if strings.Contains(v, "://") {
		return iriT(v)
	}
	return litT(v, "")
}

// nanopubQuads builds the full-IRI quad set for a claim's nanopublication, over the temp base. The npx
// signature element carries pubkey/algorithm/target always; the signature literal is added only when
// sig != "" (the two-phase trustyuri process signs the graph WITHOUT its own signature, then re-hashes
// WITH it to mint the name).
func nanopubQuads(c *trigCtx, st *claim.Statement, body map[string]any, env core.Envelope, id, creator, pubB64, sig string) []npQuad {
	P := c.prefixes
	NP := npTempBase
	sub := func(n string) string { return npTempBase + "#" + n }
	HEAD, ASSERT, PROV, PUBINFO, O, SIG := sub("Head"), sub("assertion"), sub("provenance"), sub("pubinfo"), sub("o"), sub("sig")
	var qs []npQuad
	add := func(s, p string, o npTerm, g string) { qs = append(qs, npQuad{s, p, g, o}) }

	// Head
	add(NP, rdfType+"type", iriT(P["np"]+"Nanopublication"), HEAD)
	add(NP, P["np"]+"hasAssertion", iriT(ASSERT), HEAD)
	add(NP, P["np"]+"hasProvenance", iriT(PROV), HEAD)
	add(NP, P["np"]+"hasPublicationInfo", iriT(PUBINFO), HEAD)

	by, when := str(body, "by"), str(body, "when")
	agent := c.expand(agentIRI(c, by))
	signerVerified := false
	if len(env.Signatures) > 0 {
		// Attribute to the VERIFIED signer (a trusted key that actually signed), not the self-declared
		// keyid a relabeler can forge (cold-session verified-attribution sibling: the RSA nanopublish path).
		if vk := core.VerifiedSignerKeyID(env, c.trustKeys); vk != "" {
			agent = P["agent"] + vk
			signerVerified = true
		} else {
			agent = P["agent"] + env.Signatures[0].KeyID
		}
	}

	// Assertion
	if st.PredicateType == claim.ScopePredicateType {
		scope := str(body, "scope")
		add("urn:nekton:scope:"+scope, rdfType+"type", iriT(P["nk"]+"Scope"), ASSERT)
		add("urn:nekton:scope:"+scope, P["rdfs"]+"label", litT(scope, ""), ASSERT)
	} else {
		subj := "urn:nekton:claim"
		if len(st.Subject) > 0 {
			subj = c.expand(c.hashRef(st.Subject[0].Key()))
		}
		// EXPAND the predicate to its full IRI (F1a): a stored CURIE like "gxp:reviewed" must be signed as
		// <https://kton.dev/v/gxp/reviewed>, not the bogus relative <gxp:reviewed>. The published TriG
		// re-abbreviates it with c.curie, which expands back to this exact IRI, so signed == published.
		add(subj, c.expand(uriOf(body, "predicate")), iriT(O), ASSERT)
		if obj, ok := body["object"].(map[string]any); ok {
			fkeys := make([]string, 0, len(obj))
			for k := range obj {
				fkeys = append(fkeys, k)
			}
			sort.Strings(fkeys)
			for _, k := range fkeys {
				add(O, c.expand(c.fieldIRI(k)), c.refTerm(fmt.Sprintf("%v", obj[k])), ASSERT)
			}
		}
		if ev, ok := body["evidence"].([]any); ok {
			for _, e := range ev {
				if em, ok := e.(map[string]any); ok {
					if h, ok := em["hash"].(string); ok {
						add(O, P["nk"]+"evidence", c.refTerm(h), ASSERT)
					}
				}
			}
		}
	}

	// Provenance: assert prov:wasAttributedTo only for a VERIFIED signer; otherwise carry the claimed
	// signer as unverified so a consumer never reads a forged keyid as established (verified-attribution).
	if signerVerified {
		add(ASSERT, P["prov"]+"wasAttributedTo", iriT(agent), PROV)
		add(ASSERT, P["nk"]+"signerVerified", litT("true", P["xsd"]+"boolean"), PROV)
	} else {
		add(ASSERT, P["nk"]+"claimedSigner", iriT(agent), PROV)
		add(ASSERT, P["nk"]+"signerVerified", litT("false", P["xsd"]+"boolean"), PROV)
	}
	if when != "" {
		add(ASSERT, P["prov"]+"generatedAtTime", litT(when, P["xsd"]+"dateTime"), PROV)
	}
	// context + evidence media types belong in the SIGNED graph too (they were only in the published
	// TriG before, so the signature covered a smaller graph than what was shown - F1b).
	if ctx := uriOf(body, "context"); ctx != "" {
		add(ASSERT, P["dct"]+"subject", iriT(c.expand(ctx)), PROV)
	}
	if ev, ok := body["evidence"].([]any); ok {
		for _, e := range ev {
			if em, ok := e.(map[string]any); ok {
				h, _ := em["hash"].(string)
				mt, _ := em["mediaType"].(string)
				if h != "" && mt != "" {
					add(c.expand(c.hashRef(h)), P["dct"]+"format", litT(mt, ""), PROV)
				}
			}
		}
	}

	// Publication info
	// createdBy/creator only when the publisher is known: an explicit --creator, or a VERIFIED signer -
	// never an unverified claimed keyid stamped as an established publisher (verified-attribution).
	if creator != "" {
		cb := c.expand(c.curie(creator))
		add(NP, P["pav"]+"createdBy", iriT(cb), PUBINFO)
		add(NP, P["dct"]+"creator", iriT(cb), PUBINFO)
	} else if signerVerified {
		add(NP, P["pav"]+"createdBy", iriT(agent), PUBINFO)
		add(NP, P["dct"]+"creator", iriT(agent), PUBINFO)
	}
	add(NP, P["prov"]+"wasDerivedFrom", iriT(P["pk"]+id), PUBINFO)
	if when != "" {
		add(NP, P["dct"]+"created", litT(when, P["xsd"]+"dateTime"), PUBINFO)
	}
	// seedchain profile (genesis / scope / prev) - signed, not just displayed (F1b).
	if g, _ := body["genesis"].(bool); g {
		add(NP, P["nk"]+"genesis", litT("true", P["xsd"]+"boolean"), PUBINFO)
		add(NP, P["nk"]+"scope", iriT(P["pk"]+id), PUBINFO)
	} else {
		if sc := str(body, "scope"); sc != "" {
			add(NP, P["nk"]+"scope", c.refTerm(sc), PUBINFO)
		}
		if pv := str(body, "prev"); pv != "" {
			add(NP, P["nk"]+"prev", c.refTerm(pv), PUBINFO)
		}
	}
	add(NP, P["rdfs"]+"label", litT(by, ""), PUBINFO)
	add(agent, P["rdfs"]+"label", litT(by, ""), PUBINFO)
	if len(env.Signatures) > 0 { // the DSSE <-> RSA provenance join
		add(NP, P["nk"]+"signedAs", litT("in-toto/DSSE", ""), PUBINFO)
		add(NP, P["nk"]+"signatureAlgorithm", litT("ed25519", ""), PUBINFO)
		add(NP, P["nk"]+"keyid", litT(env.Signatures[0].KeyID, ""), PUBINFO)
		add(NP, P["nk"]+"dsseSignature", litT(env.Signatures[0].Sig, ""), PUBINFO)
	}
	// npx signature element
	add(SIG, P["npx"]+"hasPublicKey", litT(pubB64, ""), PUBINFO)
	add(SIG, P["npx"]+"hasAlgorithm", litT("RSA", ""), PUBINFO)
	add(SIG, P["npx"]+"hasSignatureTarget", iriT(NP), PUBINFO)
	if sig != "" {
		add(SIG, P["npx"]+"hasSignature", litT(sig, ""), PUBINFO)
	}
	return qs
}

// canonicalize renders the quads as sorted N-Quads with the nanopub's own base collapsed to a fixed
// placeholder, so the resulting bytes (and therefore the hash and the signature) are independent of the
// not-yet-minted self URI. This is the byte string that the RSA signature and the Trusty URI cover.
func canonicalize(qs []npQuad) []byte {
	blank := func(iri string) string {
		if strings.HasPrefix(iri, npTempBase) {
			return npSelfMark + iri[len(npTempBase):]
		}
		return iri
	}
	esc := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	// Every IRI position is iriEsc'd (the same escape the TriG face uses), so a crafted object value that
	// reached the IRI path cannot inject an extra quad into the SIGNED, HASHED bytes either - signed and
	// published stay byte-consistent and injection-free.
	term := func(t npTerm) string {
		if !t.isLit {
			return "<" + iriEsc(blank(t.iri)) + ">"
		}
		s := "\"" + esc.Replace(t.lit) + "\""
		if t.dt != "" && t.dt != xsdString {
			s += "^^<" + iriEsc(t.dt) + ">"
		}
		return s
	}
	lines := make([]string, len(qs))
	for i, q := range qs {
		lines[i] = "<" + iriEsc(blank(q.s)) + "> <" + iriEsc(blank(q.p)) + "> " + term(q.o) + " <" + iriEsc(blank(q.g)) + "> ."
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

// quadsToTrig renders the EXACT signed quad set as human-readable TriG, so the published nanopub and
// the RSA-signed / Trusty-hashed bytes are one and the same graph (fixes F1b: previously the signature
// covered nanopubQuads while a separate renderTrig serializer emitted a DIFFERENT triple set). Every
// term is re-abbreviated with c.curie, whose inverse is c.expand, so parsing this TriG recovers the
// full-IRI quads that were signed. The temp self-base is rewritten to the minted Trusty base; a verifier
// re-normalizes that self-base back to the same placeholder before hashing, exactly as canonicalize does.
func quadsToTrig(c *trigCtx, qs []npQuad, base string) string {
	ref := func(iri string) string {
		if iri == npTempBase {
			return "this:"
		}
		if strings.HasPrefix(iri, npTempBase+"#") {
			return "sub:" + iri[len(npTempBase+"#"):]
		}
		return c.curie(iri)
	}
	term := func(t npTerm) string {
		if !t.isLit {
			return ref(t.iri)
		}
		s := quote(t.lit)
		if t.dt != "" && t.dt != xsdString {
			s += "^^" + c.curie(t.dt)
		}
		return s
	}
	var b strings.Builder
	keys := make([]string, 0, len(c.prefixes))
	for k := range c.prefixes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "@prefix %s: <%s> .\n", k, c.prefixes[k])
	}
	fmt.Fprintf(&b, "@prefix this: <%s> .\n@prefix sub: <%s#> .\n\n", base, base)
	// Group triples by graph, preserving first-appearance order of graphs and sorting within each so
	// the output is deterministic (matching the canonical N-Quads' stable sort).
	var order []string
	seen := map[string]bool{}
	byG := map[string][]string{}
	for _, q := range qs {
		if !seen[q.g] {
			seen[q.g] = true
			order = append(order, q.g)
		}
		byG[q.g] = append(byG[q.g], "  "+ref(q.s)+" "+ref(q.p)+" "+term(q.o)+" .")
	}
	for _, g := range order {
		lines := byG[g]
		sort.Strings(lines)
		fmt.Fprintf(&b, "%s {\n%s\n}\n\n", ref(g), strings.Join(lines, "\n"))
	}
	return b.String()
}

// trustyURI is the nanopub RA artifact code + the URL-safe base64 of the SHA-256 of the canonical RDF.
func trustyURI(canon []byte) string {
	h := sha256.Sum256(canon)
	return "RA" + base64.RawURLEncoding.EncodeToString(h[:])
}

func loadOrGenRSA(path string) (*rsa.PrivateKey, bool, error) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			blk, _ := pem.Decode(b)
			if blk == nil {
				return nil, false, fmt.Errorf("no PEM block in %s", path)
			}
			if k, e := x509.ParsePKCS8PrivateKey(blk.Bytes); e == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk, false, nil
				}
				return nil, false, fmt.Errorf("%s is not an RSA key", path)
			}
			rk, e := x509.ParsePKCS1PrivateKey(blk.Bytes)
			return rk, false, e
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	if path != "" {
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}
	return k, true, nil
}

func nanopublish(args []string) error {
	var in, out, creator, rsaKey, trustDir string
	aliasesPath := envOr("NEKTON_ALIASES", "./aliases.json")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			i++
			out = arg(args, i)
		case "--creator":
			i++
			creator = arg(args, i)
		case "--rsa":
			i++
			rsaKey = arg(args, i)
		case "--trust-keys":
			i++
			trustDir = arg(args, i)
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
		return fmt.Errorf("usage: nekton nanopublish <claim.dsse.json|sha256:id> [--rsa key.pem] [--creator IRI] [-o out.trig]")
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

	priv, generated, err := loadOrGenRSA(rsaKey)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)

	// Phase 1: sign the graph WITHOUT its own signature (pubkey present).
	unsigned := canonicalize(nanopubQuads(c, st, body, env, id, creator, pubB64, ""))
	digest := sha256.Sum256(unsigned)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Phase 2: mint the Trusty URI over the graph WITH its signature.
	signedQuads := nanopubQuads(c, st, body, env, id, creator, pubB64, sigB64)
	trusty := trustyURI(canonicalize(signedQuads))

	// Self-check (fail loudly rather than emit an unverifiable nanopub): the RSA signature must verify
	// against the phase-1 bytes, and the Trusty URI must recompute over the phase-2 bytes.
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return fmt.Errorf("internal: fresh RSA signature did not verify: %w", err)
	}
	if got := trustyURI(canonicalize(nanopubQuads(c, st, body, env, id, creator, pubB64, sigB64))); got != trusty {
		return fmt.Errorf("internal: Trusty URI not stable (%s != %s)", got, trusty)
	}

	// Publish the EXACT signed quads as TriG (single source of truth), so the bytes the RSA signature
	// and Trusty URI cover are the bytes a reader sees and re-verifies - no second serializer to drift.
	base := "https://kton.dev/np/" + trusty + "."
	trig := quadsToTrig(c, signedQuads, base)
	// Guard the renderer against silently dropping or inventing a triple: the published TriG must carry
	// exactly one statement line per signed quad. (A structural floor; the term-level round-trip is
	// guaranteed by curie/expand being inverse.)
	nStmts := 0
	for _, ln := range strings.Split(trig, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasSuffix(t, " .") && !strings.HasPrefix(t, "@prefix") {
			nStmts++
		}
	}
	if nStmts != len(signedQuads) {
		return fmt.Errorf("internal: published TriG has %d statements but %d were signed (renderer drift)", nStmts, len(signedQuads))
	}

	if generated && rsaKey == "" {
		fmt.Fprintf(os.Stderr, "note: generated an EPHEMERAL RSA key (not saved); pass --rsa key.pem to sign reproducibly.\n")
	} else if generated {
		fmt.Fprintf(os.Stderr, "note: generated a new RSA key and saved it to %s.\n", rsaKey)
	}
	fmt.Fprintf(os.Stderr, "nanopublished %s  (RSA-signed, self-verified; DSSE join kept via prov:wasDerivedFrom)\n", trusty)
	if out == "" || out == "-" {
		fmt.Print(trig)
		return nil
	}
	return os.WriteFile(out, []byte(trig), 0o644)
}
