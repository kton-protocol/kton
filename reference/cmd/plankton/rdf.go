package main

// rdf.go renders the plankton foton lineage as RDF (Turtle, PROV-O). It reuses the SAME IRIs the
// nekton nanopub export uses - pk:<hex> for a content object (a file hash or a foton id) and
// agent:<keyid> for a signer - so the two projections MERGE into one graph: a nekton claim ABOUT a
// foton and that foton's plankton lineage meet at the same pk: node. That is what lets a consumer
// reason across the whole kton (e.g. "is there a REVIEWED qc step in the LINEAGE of this model?"):
// plankton contributes the verifiable prov:used / prov:wasGeneratedBy edges, nekton the signed
// attestations. plankton documents; it does not reason - this is a pure, offline serialization (no
// net, WASM-clean), a projection you feed to a triplestore/reasoner, never an inference step.

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"kton.dev/plankton/rdf"
	"kton.dev/plankton/registry"
)

// exportRDF emits the whole registry, or - when sel names a foton id or an output hash - only that
// record's LINEAGE (a subset), so you can expose exactly the provenance a question needs.
func exportRDF(dir, sel, out string, trustKeys []ed25519.PublicKey) error {
	r, err := registry.Open(dir)
	if err != nil {
		return err
	}
	s, err := buildRDF(r, sel, trustKeys)
	if err != nil {
		return err
	}
	if out == "" || out == "-" {
		fmt.Print(s)
		return nil
	}
	return os.WriteFile(out, []byte(s), 0o644)
}

// buildRDF is rdf.Turtle; the rendering moved to the library so a linking caller (a cockpit) can
// project a registry without the CLI (proposal K8).
func buildRDF(r *registry.Registry, sel string, trustKeys []ed25519.PublicKey) (string, error) {
	return rdf.Turtle(r, sel, trustKeys)
}
