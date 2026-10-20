package registry

import "kton.dev/plankton/core"

// VerificationUnchecked is the only Verification a ReuseHit carries: nobody checked the signature.
// It is NOT `"verified": false`. A constant false carries no information, and it is the token a
// consumer reads as CHECKED AND FAILED rather than NOBODY LOOKED.
const VerificationUnchecked = "unchecked"

// ReuseHit is one prior computation matching an action key, as a consumer should see it.
//
// A cache key binds inputs+protocol, NOT outputs or signer (it can't - you look up BY inputs to FIND
// the outputs, and binding the signer would break cross-party reuse). So an action key can have
// several hits by different signers with different outputs - anyone may author a foton with these
// inputs. The hits are COMPETING matches, and DeclaredSigner is the envelope's unauthenticated keyid
// hint. A consumer picks a signer it trusts and verifies that hit.
//
// The fields are in key order, so `plankton reuse --json` prints the bytes it printed when its rows were
// maps.
type ReuseHit struct {
	// Conditions is set when the hit is a CONDITIONAL foton (SPEC §6.2): a step that read state the
	// record cannot pin. Its action key already keeps it apart from unconditional work; the mark says
	// that even this hit's own re-run need not reproduce it. The consumer decides (SPEC §11).
	Conditions     []core.Condition `json:"conditions,omitempty"`
	DeclaredSigner string           `json:"declaredSigner"` // the first signature's keyid, not verified; "" if none
	FotonID        string           `json:"fotonId"`
	Outputs        []string         `json:"outputs"`
	Verification   string           `json:"verification"`
}

// ReuseHits returns the hits for an action key in index order, each with its declared signer and
// outputs (spec §11). It is Reuse with the rows assembled, so every caller reports the same thing.
func (r *Registry) ReuseHits(actionKey string) []ReuseHit {
	ids := r.Reuse(actionKey)
	hits := make([]ReuseHit, 0, len(ids))
	for _, id := range ids {
		h := ReuseHit{FotonID: id, Verification: VerificationUnchecked}
		if env, ok := r.Envelope(id); ok && len(env.Signatures) > 0 {
			h.DeclaredSigner = env.Signatures[0].KeyID
		}
		if f, ok := r.Foton(id); ok {
			for _, o := range f.Outputs {
				h.Outputs = append(h.Outputs, o.Hash)
			}
			h.Conditions = f.Protocol.Conditions
		}
		hits = append(hits, h)
	}
	return hits
}
