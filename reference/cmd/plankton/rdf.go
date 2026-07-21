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
	"sort"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

const (
	rdfNsPK    = "https://kton.dev/o/"
	rdfNsAgent = "https://kton.dev/agent/"
	rdfNsNK    = "https://kton.dev/v/"
	rdfNsProv  = "http://www.w3.org/ns/prov#"
	rdfNsRDFS  = "http://www.w3.org/2000/01/rdf-schema#"
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

// buildRDF renders the (whole or sel-restricted) lineage to a Turtle string. trustKeys is the
// verifier's trusted key set: a foton is attributed (prov:wasAttributedTo) only to the key that
// actually signed it; a record no trusted key verifies is marked nk:signerVerified false and its
// claimed signer is carried as nk:claimedSigner (NOT prov:wasAttributedTo), so a relabelled or
// unverifiable attribution is never presented as established identity.
func buildRDF(r *registry.Registry, sel string, trustKeys []ed25519.PublicKey) (string, error) {
	var ids []string
	if sel == "" {
		ids = r.FotonIDs()
	} else {
		ids = lineageIDs(r, sel)
		if len(ids) == 0 {
			return "", fmt.Errorf("no foton lineage for %q (not a foton id or output hash in the registry)", sel)
		}
	}

	var b strings.Builder
	for _, p := range []struct{ pfx, ns string }{
		{"pk", rdfNsPK}, {"agent", rdfNsAgent}, {"nk", rdfNsNK}, {"prov", rdfNsProv}, {"rdfs", rdfNsRDFS},
	} {
		fmt.Fprintf(&b, "@prefix %s: <%s> .\n", p.pfx, p.ns)
	}
	b.WriteString("\n# plankton lineage as PROV: a foton is a prov:Activity; inputs are prov:used,\n")
	b.WriteString("# outputs prov:wasGeneratedBy. pk:<hash> nodes join nekton claims about the same hash.\n\n")

	labeled := map[string]bool{}     // entity nodes already given an rdfs:label (from an output)
	var rootInputs []string          // input nodes (ordered, deduped) that may need their own label
	inputPath := map[string]string{} // node -> relative path
	inputSeen := map[string]bool{}

	for _, id := range ids {
		f, ok := r.Foton(id)
		if !ok {
			continue
		}
		act := pkNode(id)
		fmt.Fprintf(&b, "%s a prov:Activity ;\n", act)
		fmt.Fprintf(&b, "    nk:protocolKind %s", rdfLiteral(f.Protocol.Kind))
		if ref := pkNode(f.Protocol.Ref); ref != "" {
			fmt.Fprintf(&b, " ;\n    nk:protocolRef %s", ref)
		}
		// The environment a foton was produced in (an env-spectrum id) is COVERED in its protocol
		// descriptor; emit it as a triple so a consumer/gate binds it FROM THE GRAPH, instead of
		// base64-decoding the DSSE payload out of band (rdf-interop F2). It stays tied to this exact
		// attested foton - the descriptor is part of the signed, id-covered projection.
		if envh, ok := f.Protocol.Descriptor["environment"].(string); ok {
			if en := pkNode(envh); en != "" {
				fmt.Fprintf(&b, " ;\n    nk:environment %s", en)
			}
		}
		if env, ok := r.Envelope(id); ok && len(env.Signatures) > 0 && env.Signatures[0].KeyID != "" {
			// Attribute to the VERIFIED signer (the trusted key that actually signed this foton), never the
			// self-declared keyid. If no trusted key verifies it, do NOT assert prov:wasAttributedTo -
			// carry the claimed signer as unverified so a consumer/gate never reads a forged attribution
			// as established (systemic cold-session finding: the kernel knows, the readers did not ask).
			if vk := core.VerifiedSignerKeyID(env, trustKeys); vk != "" {
				if a := agentNode(vk); a != "" {
					fmt.Fprintf(&b, " ;\n    prov:wasAttributedTo %s ;\n    nk:signerVerified true", a)
				}
			} else if a := agentNode(env.Signatures[0].KeyID); a != "" {
				fmt.Fprintf(&b, " ;\n    nk:claimedSigner %s ;\n    nk:signerVerified false", a)
			}
		}
		// prov:used one line per input; remember its path so a lineage-root input still gets a label
		for _, in := range f.Inputs {
			if n := pkNode(in.Hash); n != "" {
				fmt.Fprintf(&b, " ;\n    prov:used %s", n)
				if in.Path != "" && !inputSeen[n] {
					inputSeen[n] = true
					rootInputs = append(rootInputs, n)
					inputPath[n] = in.Path
				}
			}
		}
		b.WriteString(" .\n")
		// each output: an entity generated by this activity, derived from the inputs
		for _, o := range f.Outputs {
			on := pkNode(o.Hash)
			if on == "" {
				continue
			}
			fmt.Fprintf(&b, "%s a prov:Entity ;\n    prov:wasGeneratedBy %s", on, act)
			if o.Path != "" {
				fmt.Fprintf(&b, " ;\n    rdfs:label %s", rdfLiteral(o.Path))
				labeled[on] = true
			}
			for _, in := range f.Inputs {
				if n := pkNode(in.Hash); n != "" {
					fmt.Fprintf(&b, " ;\n    prov:wasDerivedFrom %s", n)
				}
			}
			b.WriteString(" .\n")
		}
		b.WriteString("\n")
	}

	// Inputs that are never an output (lineage roots, e.g. the dataset) get no label from the loop
	// above; declare them as labeled entities too so every node in the graph carries its path.
	var roots []string
	for _, n := range rootInputs {
		if !labeled[n] {
			roots = append(roots, n)
		}
	}
	if len(roots) > 0 {
		b.WriteString("# lineage-root inputs (never produced here): labeled so every node carries a path\n")
		for _, n := range roots {
			fmt.Fprintf(&b, "%s a prov:Entity ;\n    rdfs:label %s .\n", n, rdfLiteral(inputPath[n]))
		}
	}
	return b.String(), nil
}

// lineageIDs resolves sel to the foton ids to emit: sel as a foton id yields that foton plus every
// ancestor (via each output's lineage); sel as an output hash yields the producers of that hash and
// their ancestors. Sorted + deduped for deterministic output.
func lineageIDs(r *registry.Registry, sel string) []string {
	set := map[string]bool{}
	if f, ok := r.Foton(sel); ok {
		set[sel] = true
		for _, o := range f.Outputs {
			for _, id := range r.Lineage(o.Hash) {
				set[id] = true
			}
		}
	} else {
		for _, id := range r.Lineage(sel) {
			set[id] = true
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// pkNode renders a "sha256:<hex>" content hash as the curie pk:<hex>; returns "" for a non-hash.
// pkNode maps a content hash to its `pk:<hex>` prefixed-name node. It VALIDATES the hash through the
// kernel's own NormalizeContentHash first: a digest field is attacker-authored (a self-signed foton can
// carry any string as `subject.digest.sha256`), so an un-validated `"pk:"+rest` interpolated raw into
// Turtle lets a malformed digest like `aa ; prov:wasAttributedTo agent:X` inject forged triples - past
// the verified-signer attribution logic, because it enters through the hash field, not the signer field
// (RDF-injection, round-2 H-b). A non-normalizable digest returns "" and every call site already skips
// an empty node (`if n := pkNode(...); n != ""`), so the injected string never reaches the output.
func pkNode(hash string) string {
	n, ok := core.NormalizeContentHash(hash)
	if !ok {
		return ""
	}
	return "pk:" + strings.TrimPrefix(n, "sha256:")
}

// agentNode renders a signer keyid as the prefixed-name agent:<hex>, the SAME guard pkNode gives a
// content hash. The declared keyid (env.Signatures[0].KeyID) is attacker-authored: a self-signed foton
// can carry any string there, and it is emitted even when signerVerified is false. Interpolated raw into
// Turtle, a crafted keyid like `x .\n forged:triple .\n agent:y` would inject triples through the signer
// field (RDF-injection, round-2 H-b sibling; pkNode already closed the hash field). A keyid is a 16-hex
// prefix of a key digest, so anything outside [0-9a-f] (bounded) returns "" and the call site omits the
// attribution rather than emitting poison.
func agentNode(keyid string) string {
	if keyid == "" || len(keyid) > 64 {
		return ""
	}
	for _, c := range keyid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return "agent:" + keyid
}

// rdfLiteral renders s as a double-quoted Turtle literal, escaping the Turtle metacharacters.
func rdfLiteral(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	return "\"" + r.Replace(s) + "\""
}
