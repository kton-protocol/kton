package main

// show.go adds the compact human read that cycle-1 sessions lacked: ONE claim's subject,
// predicate, statement/object, signer, and timestamp - without dumping `export` JSON. Accepts a
// claim envelope file OR a claim id (looked up in the registry).

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
)

func showClaim(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: nekton show <claim.dsse.json | sha256:claimId>")
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
		rec, ok := r.Claim(arg)
		if !ok {
			return fmt.Errorf("no claim %q (not a file, not in registry %s)", arg, dir())
		}
		env = rec.Envelope
	}
	st, payload, err := claim.ParseEnvelope(env)
	if err != nil {
		return err
	}
	var body map[string]any
	_ = json.Unmarshal(st.Predicate, &body)

	fmt.Printf("claim:     %s\n", claim.ClaimID(payload))
	if len(st.Subject) > 0 {
		fmt.Printf("subject:   %s\n", st.Subject[0].Key())
	}
	fmt.Printf("predicate: %s\n", uriOf(body, "predicate"))
	if ctx := uriOf(body, "context"); ctx != "" {
		fmt.Printf("context:   %s\n", ctx)
	}
	if obj, ok := body["object"].(map[string]any); ok {
		fmt.Printf("object:\n")
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-12s %v\n", k, obj[k])
		}
	}
	if ev, ok := body["evidence"].([]any); ok && len(ev) > 0 {
		fmt.Printf("evidence:  %v\n", ev)
	}
	fmt.Printf("by:        %v (self-asserted label)   @ %v\n", body["by"], body["when"])
	if sc, ok := body["scope"].(string); ok && sc != "" {
		if st.PredicateType == claim.ScopePredicateType {
			fmt.Printf("scope:     %s  (this seed opens the scope; its scope id = the claim id above)\n", sc)
		} else {
			fmt.Printf("scope:     %s (prev %v)\n", sc, body["prev"])
		}
	}
	if len(env.Signatures) > 0 {
		fmt.Printf("declared keyid: %s (unverified envelope field - run `nekton verify` with the signer's key)\n", env.Signatures[0].KeyID)
	}
	return nil
}
