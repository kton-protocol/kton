package main

// verify.go is the browser VERIFY side for a SINGLE record - the check a cockpit runs before it
// takes in an entry from somewhere else.
//
// The other two surfaces almost do this, and neither is right for it. BuildGraph verifies, but
// answers with graph nodes carrying shortened ids, so a caller has to reach into an internal node
// shape to get back to one record. SealClaim does the correct thing mechanically and was being
// used for it, but it is a function for ASSEMBLING a claim; pressing it into service as a verifier
// couples callers to the authoring path and would make any change there a silent breakage here.
//
// SPEC §8 governs what this may report. The envelope's own keyid is NOT covered by the signature
// and is therefore a self-reported hint that can be forged: on success the keyid reported here is
// the one derived from the key that actually verified, and a declared keyid differing from it is
// flagged. The id is likewise re-derived from the payload, never read out of the record.
//
// No build tag: this file compiles natively too, so `go test` exercises the exact code the browser
// runs.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// verifyResult is the answer to "may I take this record in?".
type verifyResult struct {
	OK bool `json:"ok"`
	// Keyid is the keyid of the key that ACTUALLY verified the signature - the authoritative signer
	// (SPEC §8). Empty when OK is false: there is then no signer to name.
	Keyid string `json:"keyid,omitempty"`
	// DeclaredKeyid is the envelope's own claim about its signer. It is not covered by the signature,
	// so it is shown as a hint and never as an identity.
	DeclaredKeyid string `json:"declaredKeyid,omitempty"`
	// KeyidMismatch flags a declared keyid that disagrees with the verifying one (SPEC §8 SHOULD).
	// It does not make the record invalid - the signature verified - but it is worth surfacing.
	KeyidMismatch bool `json:"keyidMismatch,omitempty"`
	// Kind is "claim", "seed" or "foton": which identity rule applies to this payload.
	Kind string `json:"kind"`
	// ClaimID / FotonID: the RE-DERIVED content address, whichever one governs this payload. A
	// foton's identity is its foton id (a hash of the covered projection), not the payload hash, so
	// only the applicable field is set - reporting both would invite a caller to key on the wrong one.
	ClaimID string `json:"claimId,omitempty"`
	FotonID string `json:"fotonId,omitempty"`
	// Statement is the signed payload as it was verified, so a caller can display exactly what was
	// signed rather than re-reading the record it was handed.
	Statement json.RawMessage `json:"statement"`
}

// Verify checks one DSSE envelope against one public key and reports what was actually established.
// It returns a verdict for a well-formed envelope that simply does not verify (ok:false), and an
// error only when the input cannot be read as an envelope at all - the two are different answers
// and a cockpit needs to tell "not signed by this key" from "this is not a record".
func Verify(envelopeJSON, pubHex string) (string, error) {
	var env core.Envelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return "", fmt.Errorf("envelope is not valid JSON: %w", err)
	}
	pub, err := core.ParsePublicKeyHex(strings.TrimSpace(pubHex))
	if err != nil {
		return "", err
	}
	payload, err := env.PayloadBytes()
	if err != nil {
		return "", fmt.Errorf("envelope payload is not decodable: %w", err)
	}

	var res verifyResult
	res.Statement = json.RawMessage(payload)
	if len(env.Signatures) > 0 {
		res.DeclaredKeyid = env.Signatures[0].KeyID
	}
	// VerifiedSignerKeyID walks EVERY signature (via Envelope.Verify), not just Signatures[0]: a
	// co-signed envelope [foreign, ours] has a foreign signature first and must still verify for us
	// and be attributed to OUR key (#16, the under-reporting sibling).
	res.Keyid = core.VerifiedSignerKeyID(env, []ed25519.PublicKey{pub})
	res.OK = res.Keyid != ""
	if res.OK && res.DeclaredKeyid != "" && res.DeclaredKeyid != res.Keyid {
		res.KeyidMismatch = true
	}

	// Identity is derived from the payload, never taken from the record. A verified signature over a
	// payload says nothing about an id the sender wrote next to it.
	//
	// The predicateType is sniffed with a minimal decoder rather than core.Statement, which is the
	// PLANKTON shape: its Subject.URI is a []string (a foton's carried locators), while a nekton
	// claim subject carries `uri` as a scalar. Decoding a claim through it fails, and routing on that
	// failure would file every ordinary claim as unidentifiable.
	var head struct {
		PredicateType string `json:"predicateType"`
	}
	switch err := json.Unmarshal(payload, &head); {
	case err != nil:
		res.Kind = "unknown"
	case head.PredicateType == core.PredicateFoton:
		res.Kind = "foton"
		st, e := env.Statement() // safe here: the payload IS the plankton shape
		if e != nil {
			res.OK = false
			res.Kind = "malformed-foton"
			break
		}
		if f, e := st.ToFoton(); e == nil {
			if id, e := f.FotonID(); e == nil {
				res.FotonID = id
			}
		}
		if res.FotonID == "" {
			// A foton/v0 statement whose foton id cannot be derived has no content address, so there is
			// nothing to take in under. Refuse it rather than report a verified record with no identity.
			res.OK = false
			res.Kind = "malformed-foton"
		}
	default:
		// Claims and seeds share the claim-id rule (sha256 of the canonical payload). ParseEnvelope is
		// the gate that refuses a non-canonical payload, so an id is only ever minted for a payload
		// that canonicalizes - equal id then means equal content-as-read.
		cst, _, e := claim.ParseEnvelope(env)
		if e != nil {
			res.OK = false
			res.Kind = "malformed-claim"
			break
		}
		res.ClaimID = claim.ClaimID(payload)
		if cst.IsSeed() {
			res.Kind = "seed"
		} else {
			res.Kind = "claim"
		}
	}

	out, err := json.Marshal(res)
	return string(out), err
}
