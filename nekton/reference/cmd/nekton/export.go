package main

// export.go serializes a registry's claims as a JSON list a cockpit can JOIN to plankton's
// foton graph by subject hash (the two-layer Navigator: plankton draws the results, nekton
// hangs the claims off their subjects). Reads only via the public registry API; nekton stays
// the metadata plane and renders nothing itself.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

type exportClaim struct {
	ClaimID        string          `json:"claimId"`
	PredicateType  string          `json:"predicateType"`
	KeyID          string          `json:"keyid"`                    // the SELF-DECLARED keyid (unverified)
	VerifiedSigner string          `json:"verifiedSigner,omitempty"` // the keyid that actually signed (with --trust-keys)
	SignerVerified bool            `json:"signerVerified"`           // did a trusted key verify this claim?
	Subjects       []string        `json:"subjects"`
	Predicate      json.RawMessage `json:"predicate"`
}

type exportClaims struct {
	Title  string        `json:"title"`
	Claims []exportClaim `json:"claims"`
}

func buildClaims(dir, title string, trustKeys []ed25519.PublicKey) (*exportClaims, error) {
	r, err := registry.Open(dir)
	if err != nil {
		return nil, err
	}
	g := &exportClaims{Title: title, Claims: []exportClaim{}}
	for _, rec := range r.Records(0) {
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		keyid := ""
		if len(rec.Envelope.Signatures) > 0 {
			keyid = rec.Envelope.Signatures[0].KeyID
		}
		// Verified attribution: `keyid` is the self-declared field; verifiedSigner/signerVerified come
		// from checking WHICH trusted key actually signed this claim, so a consumer never reads the
		// unverified keyid as established identity (cold-session verified-attribution sibling: JSON export).
		vk := core.VerifiedSignerKeyID(rec.Envelope, trustKeys)
		ec := exportClaim{
			ClaimID:        rec.ClaimID,
			PredicateType:  st.PredicateType,
			KeyID:          keyid,
			VerifiedSigner: vk,
			SignerVerified: vk != "",
			Predicate:      st.Predicate,
			Subjects:       []string{}, // never emit null (renderers iterate this)
		}
		for _, s := range st.Subject {
			if k := s.Key(); k != "" {
				ec.Subjects = append(ec.Subjects, k)
			}
		}
		g.Claims = append(g.Claims, ec)
	}
	sort.Slice(g.Claims, func(i, j int) bool { return g.Claims[i].ClaimID < g.Claims[j].ClaimID })
	return g, nil
}

func exportJSON(dir, title, out string, trustKeys []ed25519.PublicKey) error {
	g, err := buildClaims(dir, title, trustKeys)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	if out == "" || out == "-" {
		fmt.Println(string(b))
		return nil
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", out, len(b))
	return nil
}
