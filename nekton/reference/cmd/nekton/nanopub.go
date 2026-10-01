package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/nanopub"
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

// loadOrGenRSA reuses the key at path, or generates one and SAVES it there. When path is empty the
// key is deliberately ephemeral.
//
// Two failures used to be silent, and both cost the caller the identity they asked for:
//
//   - ANY read error was treated as "no key here" and fell through to generating a new one. A
//     permission problem, or a directory in the way, therefore produced a different identity on
//     every run instead of an error.
//   - The save's error was discarded with `_ =`. With `--rsa /nonexistent-dir/identity.pem` the
//     command generated a key, published, exited 0, and printed "saved it to …" - and the file did
//     not exist. The next run generated a different identity again.
//
// A signature over an unsaved key still verifies against its embedded public key, so nothing
// published was wrong. What was wrong was the claim that the key had been kept.
func loadOrGenRSA(path string) (*rsa.PrivateKey, bool, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
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
		case !os.IsNotExist(err):
			// An unreadable key is NOT an absent key: refuse rather than quietly mint a new
			// identity in place of the one that was requested.
			return nil, false, fmt.Errorf("cannot read the RSA key at %s (refusing to generate a "+
				"different identity in its place): %w", path, err)
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	if path != "" {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, false, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, err := core.WriteKeyFile(path, pemBytes, 0o600, false); err != nil {
			return nil, false, fmt.Errorf("generated an RSA key but could not save it to %s, so the "+
				"identity you asked to keep would have been lost: %w", path, err)
		}
	}
	return k, true, nil
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
	env, deferredScope, _, err := readEnvelopeOrID(in)
	if err != nil {
		return err
	}
	if deferredScope != "" {
		// Not a refusal: an unresolved predecessor makes a claim INCOMPLETE here, not invalid
		// (SPEC §11), and the claim itself is genuine and signed. But a projection published from
		// this store asserts it, and the publisher should know the chain it belongs to does not
		// resolve locally - a reader who fetches the scope will find a gap.
		fmt.Fprintf(os.Stderr, "note: this claim is DEFERRED here - its prev/seed for scope %s has not "+
			"arrived, so its chain does not resolve in this store.\n", deferredScope)
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
	ts, terr := mustTemplateSet(aliasesPath)
	if terr != nil {
		return terr
	}
	c := nanopub.NewContext(ts, nil)
	if trustDir != "" {
		ks, err := loadTrustKeys(trustDir)
		if err != nil {
			return err
		}
		c.SetTrustKeys(ks)
	}
	trig := nanopub.RenderTrig(c, st, body, env, id, creator, "", "")
	if out == "" || out == "-" {
		fmt.Print(trig)
		return nil
	}
	return os.WriteFile(out, []byte(trig), 0o644)
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
		return fmt.Errorf("usage: nekton nanopublish <claim.dsse.json|sha256:id> [--rsa key.pem] " +
			"[--creator IRI] [--trust-keys <dir>] [-o out.trig]\n" +
			"  --trust-keys decides what the PUBLISHED RDF asserts about the signer: with a key that\n" +
			"  verifies, prov:wasAttributedTo; without it, only nk:claimedSigner. A nanopublication is\n" +
			"  permanent, so this is not a display option.")
	}
	env, deferredScope, _, err := readEnvelopeOrID(in)
	if err != nil {
		return err
	}
	if deferredScope != "" {
		// Not a refusal: an unresolved predecessor makes a claim INCOMPLETE here, not invalid
		// (SPEC §11), and the claim itself is genuine and signed. But a projection published from
		// this store asserts it, and the publisher should know the chain it belongs to does not
		// resolve locally - a reader who fetches the scope will find a gap.
		fmt.Fprintf(os.Stderr, "note: this claim is DEFERRED here - its prev/seed for scope %s has not "+
			"arrived, so its chain does not resolve in this store.\n", deferredScope)
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
	ts, terr := mustTemplateSet(aliasesPath)
	if terr != nil {
		return terr
	}
	c := nanopub.NewContext(ts, nil)
	if trustDir != "" {
		ks, err := loadTrustKeys(trustDir)
		if err != nil {
			return err
		}
		c.SetTrustKeys(ks)
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
	unsigned := nanopub.Canonicalize(nanopub.Quads(c, st, body, env, id, creator, pubB64, ""))
	digest := sha256.Sum256(unsigned)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Phase 2: mint the Trusty URI over the graph WITH its signature.
	signedQuads := nanopub.Quads(c, st, body, env, id, creator, pubB64, sigB64)
	trusty := nanopub.TrustyURI(nanopub.Canonicalize(signedQuads))

	// Self-check (fail loudly rather than emit an unverifiable nanopub): the RSA signature must verify
	// against the phase-1 bytes, and the Trusty URI must recompute over the phase-2 bytes.
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return fmt.Errorf("internal: fresh RSA signature did not verify: %w", err)
	}
	if got := nanopub.TrustyURI(nanopub.Canonicalize(nanopub.Quads(c, st, body, env, id, creator, pubB64, sigB64))); got != trusty {
		return fmt.Errorf("internal: Trusty URI not stable (%s != %s)", got, trusty)
	}

	// Publish the EXACT signed quads as TriG (single source of truth), so the bytes the RSA signature
	// and Trusty URI cover are the bytes a reader sees and re-verifies - no second serializer to drift.
	base := "https://kton.dev/np/" + trusty + "."
	trig := nanopub.QuadsToTrig(c, signedQuads, base)
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
