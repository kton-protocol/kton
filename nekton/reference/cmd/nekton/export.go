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
	ClaimID       string   `json:"claimId"`
	PredicateType string   `json:"predicateType"`
	KeyIDs        []string `json:"keyids"` // the SELF-DECLARED keyids on the envelope (unverified)
	// The keyid that actually signed, and the full set when several trusted keys did. One claim can
	// carry several signatures - that is what a co-signature IS - so a single field could only ever
	// answer for one of them.
	VerifiedSigner  string          `json:"verifiedSigner,omitempty"`
	VerifiedSigners []string        `json:"verifiedSigners,omitempty"`
	SignerVerified  bool            `json:"signerVerified"` // did a trusted key verify this claim?
	Subjects        []string        `json:"subjects"`
	Predicate       json.RawMessage `json:"predicate"`
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
	// The UNIQUE INDEXED claims, not the arrival feed. The feed is a record of replication events:
	// two envelopes carrying the same payload signed by different keys are two entries with ONE
	// claim id, and iterating it exported that claim twice - two rows, same id, and (with only one
	// key trusted) contradictory signerVerified. A consumer keying a map by claim id kept whichever
	// row happened to be second. The indexed view holds the merged record, whose envelope carries
	// every signature that arrived, so one logical claim is one row and the trust answer is computed
	// over all of them.
	for _, id := range r.ClaimIDs() {
		rec, ok := r.Claim(id)
		if !ok {
			continue
		}
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		ec := exportClaim{
			ClaimID:       rec.ClaimID,
			PredicateType: st.PredicateType,
			KeyIDs:        []string{},
			Predicate:     st.Predicate,
			Subjects:      []string{}, // never emit null (renderers iterate this)
		}
		for _, sig := range rec.Envelope.Signatures {
			ec.KeyIDs = append(ec.KeyIDs, sig.KeyID)
		}
		// Every trusted key that actually signed, not the first one found: a co-signed claim with two
		// trusted signers is the case the whole four-eyes idea rests on, and reporting one of them
		// loses exactly the fact that matters.
		for _, pub := range trustKeys {
			if ok, err := rec.Envelope.Verify(pub); ok && err == nil {
				ec.VerifiedSigners = append(ec.VerifiedSigners, core.KeyIDHex(pub))
			}
		}
		if len(ec.VerifiedSigners) > 0 {
			ec.VerifiedSigner = ec.VerifiedSigners[0]
			ec.SignerVerified = true
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
