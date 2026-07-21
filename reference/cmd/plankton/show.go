package main

// show.go adds the read that cycle-1 sessions missed: a compact, human view of ONE foton -
// its command, inputs, and outputs - without dumping the whole `export` graph and parsing JSON.
// Accepts a foton envelope file OR a foton id (looked up in the registry).

import (
	"fmt"
	"os"
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
	if len(args) != 1 {
		return fmt.Errorf("usage: plankton show <foton.dsse.json | sha256:fotonId>")
	}
	arg := args[0]
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
				fmt.Printf("(output %s -> produced by foton %s)\n", arg, prod[0])
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
	fmt.Printf("foton:   %s\n", id)
	fmt.Printf("kind:    %s\n", f.Protocol.Kind)
	if cmd, ok := f.Protocol.Descriptor["cmd"]; ok {
		fmt.Printf("command: %v   (RECORDED, never run by plankton)\n", cmd)
	} else if len(f.Protocol.Descriptor) > 0 {
		fmt.Printf("protocol: %v\n", f.Protocol.Descriptor)
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
