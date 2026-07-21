// Package main builds the federation graph from the content-addressed union and (crucially)
// VERIFIES every record's signature - all in pure kernel code that compiles to WebAssembly and runs
// in the browser with no server. Given the union (the {fotonId|claimId, envelope} objects) and a
// keyid->pubkey map, it returns {nodes, edges} JSON: fotons (reproducible results), claims (signed
// statements), build-on edges (who built on whose output, across repos), and about edges (a claim's
// subject). Each node carries a `verified` flag from a real Ed25519/DSSE check.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"kton.dev/plankton/core"
)

type record struct {
	FotonID  string        `json:"fotonId,omitempty"`
	ClaimID  string        `json:"claimId,omitempty"`
	Envelope core.Envelope `json:"envelope"`
}

type node struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "foton" | "claim"
	Signer      string `json:"signer"`
	By          string `json:"by,omitempty"`
	Participant string `json:"participant"` // human owner (from keyid map / the claim's `by`)
	Role        string `json:"role"`        // foton: what step; claim: the predicate; source: filename
	Kind        string `json:"kind,omitempty"` // source nodes: "dataset" | "code"
	Headline    string `json:"headline"`    // claim: short human summary
	Text        string `json:"text"`        // claim: the full signed statement
	Inputs      []fref `json:"inputs,omitempty"`  // foton: the input files (hash + name)
	Outputs     []fref `json:"outputs,omitempty"` // foton: the output files (hash + name)
	Verified    bool   `json:"verified"`
	Repro       int    `json:"repro,omitempty"` // foton: ↻N - distinct signers that produced this output hash
}

// fref is a file reference in a foton's inputs/outputs: a content hash and its recorded name.
type fref struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
}

type edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "builds-on" | "about"
}

type graph struct {
	Nodes    []node              `json:"nodes"`
	Edges    []edge              `json:"edges"`
	Locators map[string][]string `json:"locators"` // content-hash -> URIs, from signed located-at claims
	Summary  summary             `json:"summary"`
	Stats   struct {
		Fotons     int `json:"fotons"`
		Claims     int `json:"claims"`
		Verified   int `json:"verified"`
		Unverified int `json:"unverified"`
	} `json:"stats"`
}

// summary is the compact, scale-independent OVERVIEW: aggregates per participant + participant-level
// edges. It is tiny (scales with #participants, not #records), so the landing dashboard loads only
// this - never the whole union.
type summary struct {
	Totals struct {
		Participants int `json:"participants"`
		Fotons       int `json:"fotons"`
		Claims       int `json:"claims"`
		Verified     int `json:"verified"`
		Unverified   int `json:"unverified"`
	} `json:"totals"`
	Participants []partSummary `json:"participants"`
	Edges        []partEdge    `json:"edges"`
}
type partSummary struct {
	Name     string `json:"name"`
	Fotons   int    `json:"fotons"`
	Claims   int    `json:"claims"`
	Verified int    `json:"verified"`
	Total    int    `json:"total"`
}
type partEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// shortLen is the node-identity hash width. 12 hex = 48 bits was collision-grindable: an attacker could
// craft two DISTINCT sha256 artifacts sharing a 12-hex prefix (~2^24 work) so they merge into ONE node
// a reader screenshots. 32 hex = 128 bits makes a collision infeasible (~2^64). The JS viewer slices ids
// to the SAME width (keep them in lockstep).
const shortLen = 32

func short(h string) string {
	h = trimHash(h)
	if len(h) > shortLen {
		return h[:shortLen]
	}
	return h
}
func trimHash(h string) string {
	for i := 0; i < len(h); i++ {
		if h[i] == ':' {
			return h[i+1:]
		}
	}
	return h
}

// BuildGraph is the pure entry point (testable natively and callable from wasm).
func BuildGraph(unionJSON, keysJSON, namesJSON string) (string, error) {
	var recs []record
	if err := json.Unmarshal([]byte(unionJSON), &recs); err != nil {
		return "", err
	}
	keys := map[string]string{}
	_ = json.Unmarshal([]byte(keysJSON), &keys) // keyid(hex) -> pubkey(hex); optional
	names := map[string]string{}
	_ = json.Unmarshal([]byte(namesJSON), &names) // keyid(hex) -> participant name; optional

	var g graph
	g.Locators = map[string][]string{}
	producedBy := map[string][]string{} // output hash (short) -> ALL foton node ids that produced it
	claimNodes := map[string]bool{}     // short claim id -> true, so a foton input that IS a claim edges to it
	type inref struct{ h, name string }
	type finput struct {
		nodeID, participant string
		inputs              []inref
	}
	var fotonInputs []finput

	verify := func(env core.Envelope) bool {
		if len(env.Signatures) == 0 {
			return false
		}
		pubHex, ok := keys[env.Signatures[0].KeyID]
		if !ok {
			return false
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != 32 {
			return false
		}
		ok2, err := env.Verify(pub)
		return err == nil && ok2
	}

	for _, r := range recs {
		payload, err := base64.StdEncoding.DecodeString(r.Envelope.Payload)
		if err != nil {
			continue
		}
		var st map[string]any
		if json.Unmarshal(payload, &st) != nil {
			continue
		}
		keyid := ""
		if len(r.Envelope.Signatures) > 0 {
			keyid = r.Envelope.Signatures[0].KeyID
		}
		ok := verify(r.Envelope)

		if r.FotonID != "" { // a foton
			// RE-DERIVE the id from the envelope - never trust the declared fotonId in the union (the same
			// check the plankton kernel runs on load). A record whose declared id disagrees with its signed
			// content is PLANTED: use the derived id (its true identity) and force unverified, so a
			// fabricated id can't shadow a real node or fake a reproduction (cold-session WASM-kernel RED).
			fid := r.FotonID
			if cst, e := r.Envelope.Statement(); e == nil {
				if f, e := cst.ToFoton(); e == nil {
					if d, e := f.FotonID(); e == nil {
						fid = d
					} else {
						ok = false
					}
				} else {
					ok = false
				}
			} else {
				ok = false
			}
			if fid != r.FotonID {
				ok = false // declared id lies about the content
			}
			nid := short(fid)
			cmd := ""
			var inputs, outputs []fref
			if pred, _ := st["predicate"].(map[string]any); pred != nil {
				if proto, _ := pred["protocol"].(map[string]any); proto != nil {
					if d, _ := proto["descriptor"].(map[string]any); d != nil {
						cmd, _ = d["cmd"].(string)
					}
					if cmd == "" {
						cmd, _ = proto["kind"].(string)
					}
				}
				var ins []inref
				if arr, _ := pred["inputs"].([]any); arr != nil {
					for _, it := range arr {
						if m, _ := it.(map[string]any); m != nil {
							name, _ := m["name"].(string)
							if dg, _ := m["digest"].(map[string]any); dg != nil {
								if h, _ := dg["sha256"].(string); h != "" {
									ins = append(ins, inref{h: short(h), name: name})
									inputs = append(inputs, fref{Hash: short(h), Name: name})
								}
							}
						}
					}
				}
				fotonInputs = append(fotonInputs, finput{nodeID: nid, participant: names[keyid], inputs: ins})
			}
			for _, subj := range asList(st["subject"]) {
				if dg, _ := subj["digest"].(map[string]any); dg != nil {
					if h, _ := dg["sha256"].(string); h != "" {
						producedBy[short(h)] = append(producedBy[short(h)], nid) // keep ALL producers (reproduction fan-in)
						name, _ := subj["name"].(string)
						outputs = append(outputs, fref{Hash: short(h), Name: name})
					}
				}
			}
			g.Nodes = append(g.Nodes, node{ID: nid, Label: cleanRole(cmd), Type: "foton",
				Signer: keyid, Participant: names[keyid], Role: cleanRole(cmd),
				Inputs: inputs, Outputs: outputs, Verified: ok})
			g.Stats.Fotons++
		} else if r.ClaimID != "" { // a claim
			// RE-DERIVE the claim id (sha256 of the canonical payload) - never trust the declared claimId.
			// A mismatch (or a non-canonical payload) is planted/malformed: use the derived id + unverified.
			cid := r.ClaimID
			if c, e := core.CanonJSON(payload); e == nil {
				cid = core.HashBytes(c)
			} else {
				ok = false
			}
			if cid != r.ClaimID {
				ok = false
			}
			nid := short(cid)
			claimNodes[nid] = true // a foton that CONSUMES this claim (input hash == claim id) edges to it
			pred, by, subj, text, objURI := "", "", "", "", ""
			if body, _ := st["predicate"].(map[string]any); body != nil {
				if p, _ := body["predicate"].(map[string]any); p != nil {
					if u, _ := p["uri"].(string); u != "" {
						pred = lastSeg(u)
					}
				}
				by, _ = body["by"].(string)
				if obj, _ := body["object"].(map[string]any); obj != nil {
					objURI, _ = obj["uri"].(string)
					// Prefer a human sentence if the claim carries one...
					for _, k := range []string{"statement", "notes", "summary", "value", "decision"} {
						if v, _ := obj[k].(string); v != "" {
							text = v
							break
						}
					}
					// ...otherwise render the object's OWN fields, so the assertion (role=final, level=L0,
					// outcome=pass, ...) still reaches the node instead of being dropped. Sorted for a
					// stable label.
					if text == "" {
						fk := make([]string, 0, len(obj))
						for k := range obj {
							if k != "uri" {
								fk = append(fk, k)
							}
						}
						sort.Strings(fk)
						var parts []string
						for _, k := range fk {
							switch v := obj[k].(type) {
							case string:
								parts = append(parts, k+": "+v)
							case map[string]any:
								if s, _ := v["value"].(string); s != "" {
									parts = append(parts, k+": "+s)
								} else if s, _ := v["id"].(string); s != "" {
									parts = append(parts, k+": "+lastSeg(s))
								} else if s, _ := v["hash"].(string); s != "" {
									parts = append(parts, k+": "+short(s))
								}
							}
						}
						text = strings.Join(parts, ", ")
					}
				}
			}
			for _, s := range asList(st["subject"]) {
				if dg, _ := s["digest"].(map[string]any); dg != nil {
					if h, _ := dg["sha256"].(string); h != "" {
						subj = short(h)
					}
				}
			}
			// a located-at claim is a signed retrieval hint (content-hash -> URI), not a step in the
			// graph: fold it into the locator map so file details can show where the bytes live.
			if (pred == "downloadURL" || pred == "located-at") && subj != "" && objURI != "" {
				g.Locators[subj] = append(g.Locators[subj], objURI)
				continue
			}
			part := names[keyid]
			if part == "" {
				part = partFromBy(by)
			}
			g.Nodes = append(g.Nodes, node{ID: nid, Label: pred, Type: "claim", Signer: keyid, By: by,
				Participant: part, Role: pred, Headline: firstClause(text), Text: text, Verified: ok})
			if subj != "" {
				g.Edges = append(g.Edges, edge{From: nid, To: subj, Kind: "about"})
			}
			// Directional object-refs: a claim's object can reference another content hash
			// (restsOn, refines, reproduces, sameAs, identity-equivalent, …). Each becomes a directional
			// edge from this claim to that target, labelled with the relation - so "A refines B",
			// "A reproduces B" are first-class, navigable, reason-over-able links, not prose.
			if objm, _ := st["predicate"].(map[string]any); objm != nil {
				if obj, _ := objm["object"].(map[string]any); obj != nil {
					for k, v := range obj {
						if rh := refHash(v); rh != "" {
							g.Edges = append(g.Edges, edge{From: nid, To: short(rh), Kind: k})
						}
					}
				}
			}
			g.Stats.Claims++
		}
		if ok {
			g.Stats.Verified++
		} else {
			g.Stats.Unverified++
		}
	}

	// build-on edges + SOURCE nodes. An input produced by another foton -> a builds-on edge to it.
	// An input produced by NO foton is an external source (a raw dataset or a script) -> make it a
	// node so the original data is findable and you can start a pedigree from it.
	sources := map[string]bool{}
	for _, fi := range fotonInputs {
		for _, in := range fi.inputs {
			if prods, ok := producedBy[in.h]; ok {
				// Draw a builds-on edge to EVERY foton that produced this input, not just the last one -
				// a reproduced artifact (N fotons, same output hash) keeps its full fan-in instead of
				// collapsing consumer edges onto one producer (cold-session multi-producer finding).
				for _, prod := range prods {
					if prod != fi.nodeID {
						g.Edges = append(g.Edges, edge{From: fi.nodeID, To: prod, Kind: "builds-on"})
					}
				}
				continue
			}
			// An input that IS a claim (a foton consuming a review/verdict corpus) edges to the CLAIM
			// node, not a generic source node - and avoids colliding a source node with the claim's id.
			if claimNodes[in.h] {
				g.Edges = append(g.Edges, edge{From: fi.nodeID, To: in.h, Kind: "consumes"})
				continue
			}
			if !sources[in.h] {
				sources[in.h] = true
				g.Nodes = append(g.Nodes, node{ID: in.h, Type: "source", Kind: sourceKind(in.name),
					Role: baseName(in.name), Participant: fi.participant})
			}
			g.Edges = append(g.Edges, edge{From: fi.nodeID, To: in.h, Kind: "builds-on"})
		}
	}
	// Reproduction: when >1 foton produced the SAME output hash, link them with `reproduces` edges (a
	// star to the first producer) so the fan-in is visible even without a downstream consumer.
	for _, prods := range producedBy {
		for i := 1; i < len(prods); i++ {
			if prods[i] != prods[0] {
				g.Edges = append(g.Edges, edge{From: prods[i], To: prods[0], Kind: "reproduces"})
			}
		}
	}
	// ↻N per foton: the number of DISTINCT SIGNERS that produced this foton's output(s). Records are
	// single-signed (foton immutability -> reproduction is distinct producer fotons, not multi-sig on one
	// record), so an output's reproduction level is the count of distinct signer keyids across ALL fotons
	// that produced that exact output hash. Surfaced as node.repro so the union-mode viewer badges ↻N
	// natively - matching the mirror's markers and the JS lens, instead of only showing fan-in edges.
	// SECURITY: count only VERIFIED producers. node.Signer is the DECLARED Signatures[0].KeyID; without the
	// Verified gate an attacker forges N fotons for one output with N distinct declared keyids (no valid
	// signatures) and inflates ↻N for free (round-2 finding: the reproduction count was forgeable). Verified
	// means the signature validated against the pubkey for that keyid, so for a verified node the declared
	// keyid IS the real signer. Inflating ↻N then requires N genuine signing keys - a sybil/identity concern
	// that belongs to the attested-identity layer, not this count.
	signerOf := map[string]string{}
	for i := range g.Nodes {
		if g.Nodes[i].Type == "foton" && g.Nodes[i].Verified {
			signerOf[g.Nodes[i].ID] = g.Nodes[i].Signer
		}
	}
	reproOf := map[string]int{}
	for h, prods := range producedBy {
		seen := map[string]bool{}
		for _, nid := range prods {
			if s := signerOf[nid]; s != "" {
				seen[s] = true
			}
		}
		reproOf[h] = len(seen)
	}
	for i := range g.Nodes {
		if g.Nodes[i].Type != "foton" {
			continue
		}
		for _, o := range g.Nodes[i].Outputs {
			if reproOf[o.Hash] > g.Nodes[i].Repro {
				g.Nodes[i].Repro = reproOf[o.Hash]
			}
		}
	}
	// resolve "about" edges that point at an output hash to its producing foton - only when there is
	// exactly ONE producer (unambiguous); a reproduced artifact keeps the hash target (a ref node) so
	// the claim is not silently re-pointed at one arbitrary producer.
	for i := range g.Edges {
		if g.Edges[i].Kind == "about" {
			if prods, ok := producedBy[g.Edges[i].To]; ok && len(prods) == 1 {
				g.Edges[i].To = prods[0]
			}
		}
	}

	// Dangling edge endpoints (e.g. an env-spectrum a claim `qualifies-as`, or a file a claim
	// references) become lightweight REF nodes so every directional relation renders. Label from a
	// located-at filename when we have one, else the short hash.
	present := map[string]bool{}
	for _, n := range g.Nodes {
		present[n.ID] = true
	}
	reflabel := func(id string) string {
		for _, u := range g.Locators[id] {
			if i := strings.LastIndex(u, "/"); i >= 0 && i+1 < len(u) {
				return u[i+1:]
			}
		}
		return id
	}
	for _, e := range g.Edges {
		for _, id := range [2]string{e.From, e.To} {
			if !present[id] {
				present[id] = true
				g.Nodes = append(g.Nodes, node{ID: id, Type: "ref", Role: reflabel(id)})
			}
		}
	}

	// summary: aggregate by participant + participant-level edges (the scale-independent overview)
	nodePart := map[string]string{}
	agg := map[string]*partSummary{}
	order := []string{}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		nodePart[n.ID] = n.Participant
		if n.Type == "source" || n.Type == "ref" {
			continue // external inputs / bare references aren't a participant's signed records
		}
		ps := agg[n.Participant]
		if ps == nil {
			ps = &partSummary{Name: n.Participant}
			agg[n.Participant] = ps
			order = append(order, n.Participant)
		}
		if n.Type == "foton" {
			ps.Fotons++
		} else {
			ps.Claims++
		}
		ps.Total++
		if n.Verified {
			ps.Verified++
		}
	}
	type pk struct{ from, to, kind string }
	pc := map[pk]int{}
	for _, e := range g.Edges {
		pf, pt := nodePart[e.From], nodePart[e.To]
		if pf == "" || pt == "" || pf == pt {
			continue // participant-level view drops within-participant lineage
		}
		pc[pk{pf, pt, e.Kind}]++
	}
	sort.Strings(order)
	for _, name := range order {
		g.Summary.Participants = append(g.Summary.Participants, *agg[name])
	}
	for k, c := range pc {
		g.Summary.Edges = append(g.Summary.Edges, partEdge{From: k.from, To: k.to, Kind: k.kind, Count: c})
	}
	// SECURITY: count only participants with >=1 VERIFIED record. len(agg) counts distinct DECLARED
	// participants (agg is keyed by names[declared Signatures[0].KeyID]), so forged fotons signed by
	// unpublished keys mint fake participants and inflate the headline count - the same round-2
	// forgeability as the ↻N badge. A participant with zero verified records is unattested noise.
	verifiedParts := 0
	for _, ps := range agg {
		if ps.Verified > 0 {
			verifiedParts++
		}
	}
	g.Summary.Totals.Participants = verifiedParts
	g.Summary.Totals.Fotons = g.Stats.Fotons
	g.Summary.Totals.Claims = g.Stats.Claims
	g.Summary.Totals.Verified = g.Stats.Verified
	g.Summary.Totals.Unverified = g.Stats.Unverified

	out, err := json.Marshal(g)
	return string(out), err
}

func asList(v any) []map[string]any {
	arr, _ := v.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, _ := it.(map[string]any); m != nil {
			out = append(out, m)
		}
	}
	return out
}
func lastSeg(u string) string {
	last := u
	for i := len(u) - 1; i >= 0; i-- {
		if u[i] == '/' || u[i] == '#' { // '#' handles fragment IRIs (dcat#downloadURL, prov#used, …)
			last = u[i+1:]
			break
		}
	}
	return last
}

// cleanRole turns a foton's command into a readable step name:
// "python work/step5_neighbors.py" -> "neighbors"; "coarse_map.py" -> "coarse map";
// "fine_split2.py" -> "fine split".
func cleanRole(cmd string) string {
	s := cmd
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".py")
	if strings.HasPrefix(s, "step") {
		if j := strings.IndexByte(s, '_'); j >= 0 {
			s = s[j+1:]
		}
	}
	s = strings.TrimRight(s, "0123456789")
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return cmd
	}
	return s
}

// firstClause is a short human headline from a signed statement.
func firstClause(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.IndexAny(t, ".:;"); i > 3 && i < 80 {
		return strings.TrimSpace(t[:i])
	}
	if len(t) > 64 {
		return strings.TrimSpace(t[:64]) + "…"
	}
	return t
}

// refHash extracts a content hash from an object-field value: a bare "sha256:…" string, a
// {hash:"sha256:…"} ref, or a {digest:{sha256:…}} in-toto descriptor. Empty if the value isn't a ref.
func refHash(v any) string {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "sha256:") {
			return x
		}
	case map[string]any:
		if h, _ := x["hash"].(string); strings.HasPrefix(h, "sha256:") {
			return h
		}
		if dg, _ := x["digest"].(map[string]any); dg != nil {
			if h, _ := dg["sha256"].(string); h != "" {
				return "sha256:" + h
			}
		}
	}
	return ""
}

// sourceKind classifies an external input as raw "dataset" or "code".
func sourceKind(name string) string {
	l := strings.ToLower(name)
	for _, e := range []string{".py", ".r", ".sh", ".js", ".go", ".ipynb", ".jl"} {
		if strings.HasSuffix(l, e) {
			return "code"
		}
	}
	if strings.HasPrefix(l, "work/") || strings.HasPrefix(l, "src/") || strings.HasPrefix(l, "scripts/") {
		return "code"
	}
	return "dataset"
}

func baseName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	if name == "" {
		return "source"
	}
	return name
}

// partFromBy maps a claim's `by` to a participant handle: "CN=Participant-A" -> "pfed-a".
func partFromBy(by string) string {
	u := strings.ToLower(by)
	for _, x := range []string{"a", "b", "c"} {
		if strings.Contains(u, "participant-"+x) {
			return "pfed-" + x
		}
	}
	if i := strings.Index(by, "CN="); i >= 0 {
		return by[i+3:]
	}
	return by
}
