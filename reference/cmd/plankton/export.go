package main

// export.go renders a registry (a horizon) as a single graph JSON a navigator can draw:
// files and fotons (edges). "Leaves" are output files no foton consumes - the gallery a Lens
// shows. Reads only via the public registry API (Records); plankton stays the metadata plane.
// Claims ABOUT these results (verdicts, sign-offs, …) come from a separate `nekton export`; a
// cockpit joins the two by subject hash (the two-layer Navigator).

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

type exportFile struct {
	Hash       string   `json:"hash"`
	Paths      []string `json:"paths"`
	ProducedBy string   `json:"producedBy,omitempty"`
	IsOutput   bool     `json:"isOutput"`
	IsInput    bool     `json:"isInput"`
	Leaf       bool     `json:"leaf"`
}

type exportFoton struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Ref     string   `json:"ref"`
	Inputs  []string `json:"inputs"`
	Outputs []string `json:"outputs"`
	// The record's own refs (hash + relative path), so a consumer reading this export never has to
	// open an envelope to learn which name a hash had IN THIS foton. Files[].Paths is the union over
	// all fotons and cannot answer that.
	InputRefs  []core.FileRef `json:"inputRefs"`
	OutputRefs []core.FileRef `json:"outputRefs"`
	Descriptor map[string]any `json:"descriptor,omitempty"`
	KeyIDs     []string       `json:"keyids"` // the SELF-DECLARED keyids on the envelope (unverified)
	// Every trusted key that actually signed, as in `nekton export`: a foton's signatures are unioned
	// onto one record, so several independent producers are several verified signers.
	VerifiedSigner  string   `json:"verifiedSigner,omitempty"`
	VerifiedSigners []string `json:"verifiedSigners,omitempty"`
	// "verified" | "failed" | "unchecked" - the same three words as `nekton export`. Without
	// --trust-keys nothing was checked, and that must not read as a verdict.
	SignerVerified string `json:"signerVerified"`
}

type exportGraph struct {
	Title  string        `json:"title"`
	Files  []exportFile  `json:"files"`
	Fotons []exportFoton `json:"fotons"`
}

func buildGraph(dir, title string, trustKeys []ed25519.PublicKey) (*exportGraph, error) {
	r, err := registry.Open(dir)
	if err != nil {
		return nil, err
	}
	files := map[string]*exportFile{}
	touch := func(ref core.FileRef) *exportFile {
		f := files[ref.Hash]
		if f == nil {
			f = &exportFile{Hash: ref.Hash}
			files[ref.Hash] = f
		}
		if ref.Path != "" {
			has := false
			for _, p := range f.Paths {
				if p == ref.Path {
					has = true
				}
			}
			if !has {
				f.Paths = append(f.Paths, ref.Path)
			}
		}
		return f
	}

	g := &exportGraph{Title: title}
	// The UNIQUE indexed fotons, not the arrival feed: a second producer's signature is unioned onto
	// the existing record, and iterating the feed would emit that foton twice with (given one trusted
	// key) contradictory verdicts - the defect `nekton export` fixed for claims.
	for _, id := range r.FotonIDs() {
		f, ok := r.Foton(id)
		if !ok {
			continue
		}
		env, _ := r.Envelope(id)
		ef := exportFoton{ID: id, Kind: f.Protocol.Kind, Ref: f.Protocol.Ref, Descriptor: f.Protocol.Descriptor,
			InputRefs: []core.FileRef{}, OutputRefs: []core.FileRef{}, KeyIDs: []string{}}
		for _, in := range f.Inputs {
			touch(in).IsInput = true
			ef.Inputs = append(ef.Inputs, in.Hash)
			ef.InputRefs = append(ef.InputRefs, in)
		}
		for _, out := range f.Outputs {
			of := touch(out)
			of.IsOutput = true
			of.ProducedBy = id
			ef.Outputs = append(ef.Outputs, out.Hash)
			ef.OutputRefs = append(ef.OutputRefs, out)
		}
		for _, sig := range env.Signatures {
			ef.KeyIDs = append(ef.KeyIDs, sig.KeyID)
		}
		for _, pub := range trustKeys {
			if ok, err := env.Verify(pub); ok && err == nil {
				ef.VerifiedSigners = append(ef.VerifiedSigners, core.KeyIDHex(pub))
			}
		}
		switch {
		case len(trustKeys) == 0:
			ef.SignerVerified = "unchecked"
		case len(ef.VerifiedSigners) > 0:
			ef.VerifiedSigner = ef.VerifiedSigners[0]
			ef.SignerVerified = "verified"
		default:
			ef.SignerVerified = "failed"
		}
		g.Fotons = append(g.Fotons, ef)
	}
	// Non-foton statements are not plankton's concern (they live in nekton); they are not indexed
	// as fotons and so never reach this loop.

	for _, f := range files {
		f.Leaf = f.IsOutput && !f.IsInput
		g.Files = append(g.Files, *f)
	}
	sort.Slice(g.Files, func(i, j int) bool { return g.Files[i].Hash < g.Files[j].Hash })
	return g, nil
}

// exportJSON writes the graph JSON for the registry to out (or stdout if "-").
func exportJSON(dir, title, out string, trustKeys []ed25519.PublicKey) error {
	g, err := buildGraph(dir, title, trustKeys)
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
