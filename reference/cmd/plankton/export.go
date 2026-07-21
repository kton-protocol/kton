package main

// export.go renders a registry (a horizon) as a single graph JSON a navigator can draw:
// files and fotons (edges). "Leaves" are output files no foton consumes - the gallery a Lens
// shows. Reads only via the public registry API (Records); plankton stays the metadata plane.
// Claims ABOUT these results (verdicts, sign-offs, …) come from a separate `nekton export`; a
// cockpit joins the two by subject hash (the two-layer Navigator).

import (
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
}

type exportGraph struct {
	Title  string        `json:"title"`
	Files  []exportFile  `json:"files"`
	Fotons []exportFoton `json:"fotons"`
}

func buildGraph(dir, title string) (*exportGraph, error) {
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
	for _, rec := range r.Records(0) {
		st, err := rec.Envelope.Statement()
		if err != nil {
			continue
		}
		if st.PredicateType == core.PredicateFoton {
			f, err := st.ToFoton()
			if err != nil {
				continue
			}
			id, _ := f.FotonID()
			ef := exportFoton{ID: id, Kind: f.Protocol.Kind, Ref: f.Protocol.Ref}
			for _, in := range f.Inputs {
				touch(in).IsInput = true
				ef.Inputs = append(ef.Inputs, in.Hash)
			}
			for _, out := range f.Outputs {
				of := touch(out)
				of.IsOutput = true
				of.ProducedBy = id
				ef.Outputs = append(ef.Outputs, out.Hash)
			}
			g.Fotons = append(g.Fotons, ef)
		}
		// Non-foton statements are not plankton's concern (they live in nekton); skip.
	}

	for _, f := range files {
		f.Leaf = f.IsOutput && !f.IsInput
		g.Files = append(g.Files, *f)
	}
	sort.Slice(g.Files, func(i, j int) bool { return g.Files[i].Hash < g.Files[j].Hash })
	return g, nil
}

// exportJSON writes the graph JSON for the registry to out (or stdout if "-").
func exportJSON(dir, title, out string) error {
	g, err := buildGraph(dir, title)
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
