package registry

// reproduction.go answers the two questions a consumer asks about REPRODUCTION, over indexes this
// registry already holds. They lived inline in the plankton CLI, which meant a cockpit could only
// get them by running a binary and parsing its output - while every other capability it needs
// (authoring, verifying, reading, material, scopes) is a package it can link.
//
// They are methods rather than a package of their own because the answers are joins over byOutput,
// the envelopes and the normalized-output index: state this type owns. A separate package would
// have to be handed the registry anyway.
//
// The reason to lift them is not convenience. A consumer that must not take a reproduction level
// from whoever is asking has to RUN the comparison; if the only implementation is a CLI, every
// integrator writes a second one, and two implementations of an identity rule are two opinions
// about identity.

import (
	"crypto/ed25519"
	"fmt"

	"kton.dev/plankton/core"
)

// Producer is one foton that produced the queried output, and what is known about who signed it.
type Producer struct {
	FotonID string
	// KeyID is the signer. With trusted keys it is a key that VERIFIABLY signed this envelope; with
	// none it is the envelope's self-declared keyid, which is not covered by the DSSE signature and
	// is therefore forgeable.
	KeyID    string
	Verified bool
}

// Reproductions is the answer to "how many INDEPENDENT parties produced these bytes?".
//
// Verified is the field to branch on. False means the count is self-declared: the keyids were read
// from envelopes without checking them, so a relabelled keyid inflates the count and attributes a
// reproduction to someone who never signed. A reader that treats the two cases alike has no ↻N worth
// the name.
type Reproductions struct {
	Output            string
	Producers         []Producer
	DistinctSigners   int
	ProducerFotons    int
	ExcludedUntrusted int // held a signature, but none from a trusted key
	Verified          bool
}

// Reproductions counts distinct independent producers of outputHash.
//
// With trusted keys, a producer counts once per trusted key that ACTUALLY signed its envelope - a
// merged twin can carry several co-signatures over one payload, and each is an independent party.
// Without them nothing is verified and Verified is false.
//
// Counted over THIS registry only. A federated count is an aggregator's answer, not a store's.
func (r *Registry) Reproductions(outputHash string, trusted []ed25519.PublicKey) Reproductions {
	h := outputHash
	if n, ok := core.NormalizeContentHash(h); ok {
		h = n
	}
	prods := r.Producer(h)
	out := Reproductions{Output: h, ProducerFotons: len(prods), Verified: len(trusted) > 0,
		Producers: []Producer{}}
	signers := map[string]bool{}
	for _, id := range prods {
		env, ok := r.Envelope(id)
		if !ok || len(env.Signatures) == 0 {
			continue
		}
		if len(trusted) == 0 {
			kid := env.Signatures[0].KeyID // self-declared, UNVERIFIED
			out.Producers = append(out.Producers, Producer{FotonID: id, KeyID: kid})
			signers[kid] = true
			continue
		}
		matched := false
		for _, pub := range trusted {
			if okv, verr := env.Verify(pub); okv && verr == nil {
				kid := core.KeyIDHex(pub)
				out.Producers = append(out.Producers, Producer{FotonID: id, KeyID: kid, Verified: true})
				signers[kid] = true
				matched = true
			}
		}
		if !matched {
			out.ExcludedUntrusted++ // signed by no trusted key -> does not count
		}
	}
	out.DistinctSigners = len(signers)
	return out
}

// Reproduction is the answer to "does cand reproduce ref, and at which level?".
type Reproduction struct {
	Matches bool
	Level   string // "L0" | "L1"; empty when Matches is false
	Via     string // the normalizer potential an L1 match went through
}

// Reproduces compares two OUTPUT HASHES and reports the level the comparison reached.
//
// L0 is byte identity. L1 is identity after the SAME normalizer potential - `via` names a POTENTIAL
// (a protocol ref or a normalizer foton id), not a kind: two different normalizers of the same kind
// are different comparisons. L2 (within tolerance) is a comparator's signed verdict, never a kernel
// check, so it is not produced here.
//
// Both arguments must BE content hashes. Equality of two malformed strings is not a reproduction -
// the level says "the same output bytes", and a string that names no bytes cannot match one.
//
// An L1 result carries an obligation the caller must discharge: it holds only if the normalizer is
// itself L0-qualified. That is why Via is reported rather than folded away.
func (r *Registry) Reproduces(refHash, candHash, via string) (Reproduction, error) {
	ref, ok := core.NormalizeContentHash(refHash)
	if !ok {
		return Reproduction{}, fmt.Errorf("%q is not a content hash - reproduces compares OUTPUT HASHES, "+
			"and two equal malformed strings are not a reproduction", refHash)
	}
	cand, ok := core.NormalizeContentHash(candHash)
	if !ok {
		return Reproduction{}, fmt.Errorf("%q is not a content hash - reproduces compares OUTPUT HASHES, "+
			"and two equal malformed strings are not a reproduction", candHash)
	}
	// `via` may be a foton id or a protocol ref, so it is normalized only when it IS a content hash;
	// any other spelling stays as given and simply resolves to no normalized output below.
	if n, ok := core.NormalizeContentHash(via); ok {
		via = n
	}
	if ref == cand {
		return Reproduction{Matches: true, Level: "L0"}, nil
	}
	if via != "" {
		if nr := r.NormalizedOutput(ref, via); nr != "" && nr == r.NormalizedOutput(cand, via) {
			return Reproduction{Matches: true, Level: "L1", Via: via}, nil
		}
	}
	return Reproduction{Via: via}, nil
}
