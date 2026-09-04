package main

// show.go adds the read that cycle-1 sessions missed: a compact, human view of ONE foton -
// its command, inputs, and outputs - without dumping the whole `export` graph and parsing JSON.
// Accepts a foton envelope file OR a foton id (looked up in the registry).

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// locators renders a FileRef's carried --located URIs (where the bytes live), or "" if none.
func locators(uris []string) string {
	if len(uris) == 0 {
		return ""
	}
	return "  @ " + strings.Join(uris, " , ")
}

func show(args []string) error {
	asJSON := false
	var pos []string
	for _, a := range args {
		if a == "--json" {
			asJSON = true
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: plankton show <foton.dsse.json | sha256:fotonId> [--json]")
	}
	arg := pos[0]
	var env core.Envelope
	if _, err := os.Stat(arg); err == nil {
		env, err = readEnvelope(arg)
		if err != nil {
			return err
		}
	} else {
		r, err := registry.Open(dir())
		if err != nil {
			return err
		}
		// a foton id or an output hash: fold to canonical lowercase (SPEC §5.1) so a bare/uppercase
		// hash resolves under the stored key.
		if norm, ok := core.NormalizeContentHash(arg); ok {
			arg = norm
		}
		e, ok := r.Envelope(arg)
		if !ok {
			// arg may be an OUTPUT hash rather than a foton id - resolve it to its producer foton
			// (cycle-2 finding: sessions naturally reach for the output hash they just computed).
			if prod := r.Producer(arg); len(prod) > 0 {
				if !asJSON {
					fmt.Printf("(output %s -> produced by foton %s)\n", arg, prod[0])
				}
				e, ok = r.Envelope(prod[0])
			}
		}
		if !ok {
			return fmt.Errorf("no foton %q (not a file, not a foton id or output hash in registry %s)", arg, dir())
		}
		env = e
	}
	st, err := env.Statement()
	if err != nil {
		return err
	}
	f, err := st.ToFoton()
	if err != nil {
		return fmt.Errorf("%q is not a foton (%w)", arg, err)
	}
	id, _ := f.FotonID()

	if asJSON {
		return showJSON(id, f, env)
	}
	return showHuman(id, f, env)
}

// showHuman renders one foton for a person. Split out from show() so both renderings are
// testable and neither can quietly drift from the other.
func showHuman(id string, f *core.Foton, env core.Envelope) error {

	fmt.Printf("foton:   %s\n", id)
	fmt.Printf("kind:    %s\n", f.Protocol.Kind)
	if cmd, ok := f.Protocol.Descriptor["cmd"]; ok {
		fmt.Printf("command: %v   (RECORDED, never run by plankton)\n", cmd)
	}
	// Everything else in the descriptor, environment first. These are COVERED fields (SPEC §6.5):
	// --environment and --env-ref change the foton id, so two fotons over the same inputs, outputs
	// and cmd but different environments are different fotons. This used to print nothing at all -
	// the branch that would have shown the rest of the descriptor sat behind `else if`, and author
	// always sets a cmd, so it was unreachable. A peer therefore could not see what a reproduction
	// commits to (#54). Print by name, then whatever else is there, so nothing stays invisible.
	for _, k := range []string{"environment", "envRef"} {
		if v, ok := f.Protocol.Descriptor[k]; ok {
			fmt.Printf("%-12s %v   (COVERED - part of this foton's identity)\n", k+":", v)
		}
	}
	var rest []string
	for k := range f.Protocol.Descriptor {
		switch k {
		case "cmd", "environment", "envRef":
		default:
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		fmt.Printf("%-12s %v\n", k+":", f.Protocol.Descriptor[k])
	}
	fmt.Printf("inputs:\n")
	for _, in := range f.Inputs {
		fmt.Printf("  %-28s %s%s\n", in.Path, in.Hash, locators(in.URI))
	}
	fmt.Printf("outputs:\n")
	for _, out := range f.Outputs {
		fmt.Printf("  %-28s %s%s\n", out.Path, out.Hash, locators(out.URI))
	}
	if len(env.Signatures) > 0 {
		fmt.Printf("declared keyid: %s (unverified envelope field - run `plankton verify` with the signer's key)\n", env.Signatures[0].KeyID)
	}
	return nil
}

// showJSON emits the same foton structurally, so a consumer does not have to parse the prose above
// (the argument #39 made for `nekton about`/`by`). The descriptor is emitted whole - that is the
// point of #54: no field of it can be invisible here, because none of them are named.
func showJSON(id string, f *core.Foton, env core.Envelope) error {
	type ref struct {
		Path string   `json:"path,omitempty"`
		Hash string   `json:"hash,omitempty"`
		URI  []string `json:"uri,omitempty"`
	}
	refs := func(in []core.FileRef) []ref {
		out := make([]ref, 0, len(in))
		for _, r := range in {
			out = append(out, ref{Path: r.Path, Hash: r.Hash, URI: r.URI})
		}
		return out
	}
	keyids := make([]string, 0, len(env.Signatures))
	for _, sg := range env.Signatures {
		keyids = append(keyids, sg.KeyID)
	}
	b, err := json.MarshalIndent(map[string]any{
		"fotonId":  id,
		"protocol": f.Protocol,
		"inputs":   refs(f.Inputs),
		"outputs":  refs(f.Outputs),
		// DECLARED, not verified - the envelope says so; `plankton verify` is what checks it.
		"declaredKeyids": keyids,
		// The signed envelope itself. A consumer that has to VERIFY needs the bytes the signature
		// is over, and the projection above is not those bytes. Without this the only route to them
		// was parsing the store - which is what an abstraction over the layout exists to prevent,
		// and what #41 showed fails silently (#85). Symmetric with `nekton about --json`.
		"envelope": env,
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// printJSON is the one JSON writer for plankton's read surface, so `show`, `producer`/`uses`/
// `lineage` and `reproductions` cannot drift on formatting.
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// nullableVia renders --via as JSON null when absent, so a consumer can tell "compared raw" from
// "compared through a normalizer" without string-testing an empty value.
func nullableVia(via string) any {
	if via == "" {
		return nil
	}
	return via
}
