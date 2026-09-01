package main

// seed.go exposes the ONE structural grammar the nekton kernel admits (SPEC §7.4): a scope,
// born from a signed seed, that forms a hash-chain and may name a parent. This is how a
// "subnekton" is created - a bounded, federatable sub-registry whose whole log can be vouched
// for wholesale. The lab commons (templates, aliases, ontology) is delivered as exactly this:
// a seeded subnekton the sessions mirror. The kernel already enforces the grammar; this just
// gives it a command so a session need not hand-write a scope/v0 statement.

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"kton.dev/nekton/claim"
)

// whenOr returns an explicit --when, or the wall clock when none was given. `when` is COVERED by
// the claim id, so on a seed it is an input to a permanent identifier: seeding the same scope with
// the same key from the same inputs twice used to open two different scopes (#42). An explicit
// --when is what makes a corpus rebuildable to the same ids.
//
// It is validated here rather than only at ingest: a bad timestamp that is caught after signing has
// already been signed, and the signature is over the garbage.
func whenOr(when string) (string, error) {
	if when == "" {
		return time.Now().UTC().Format(time.RFC3339), nil
	}
	if _, err := time.Parse(time.RFC3339, when); err != nil {
		return "", fmt.Errorf("--when %q is not RFC 3339 (want e.g. 2026-07-16T00:00:00Z): %v", when, err)
	}
	return when, nil
}

// seed creates + signs a scope-genesis statement and prints the scope id (its claim id), which
// scoped claims then reference via --scope. A seed carries genesis:true and no prev (SPEC §7.4).
func seed(args []string) error {
	var name, by, parent, keyPath, out, regDir, when string
	addFlag := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add":
			addFlag = true
		case "--registry":
			i++
			regDir = arg(args, i)
		case "--by":
			i++
			by = arg(args, i)
		case "--parent":
			i++
			parent = arg(args, i)
		case "--when":
			i++
			when = arg(args, i)
		case "--sign":
			i++
			keyPath = arg(args, i)
		case "-o":
			i++
			out = arg(args, i)
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			name = args[i]
		}
	}
	if name == "" || keyPath == "" {
		return fmt.Errorf("usage: nekton seed <scope-name> --sign key.key [--by ID] [--parent <parentSeedId>] [-o out]")
	}
	priv, err := loadPriv(keyPath)
	if err != nil {
		return err
	}
	if by == "" {
		by = "key:" + keyidHex(priv.Public().(ed25519.PublicKey))
	}
	stamp, err := whenOr(when)
	if err != nil {
		return err
	}
	body := map[string]any{
		"scope":   name,
		"genesis": true,
		"by":      by,
		"when":    stamp,
	}
	if parent != "" {
		if strings.HasPrefix(parent, "sha256:") {
			body["parent"] = map[string]any{"digest": map[string]any{"sha256": bareHash(parent)}}
		} else {
			body["parent"] = map[string]any{"uri": parent}
		}
	}
	spec := claimSpec{
		Subject:       []subjSpec{{URI: "urn:nekton:scope:" + name}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: body,
	}
	if out == "" && !addFlag {
		out = "seed." + strings.ReplaceAll(name, "/", "-") + ".dsse.json"
	}
	fmt.Printf("seed scope %q", name)
	if parent != "" {
		fmt.Printf(" (parent %s)", parent)
	}
	fmt.Println()
	// signClaim prints "claim <id> ..." - that <id> IS the scope id to pass as --scope.
	if err := signClaim(spec, priv, out, addFlag, regDir); err != nil {
		return err
	}
	fmt.Println("  ^ this claim id is the SCOPE id.")
	fmt.Println("    --scope <thisId> on EVERY claim in the scope (it never changes).")
	fmt.Println("    --prev  = this id for the FIRST claim, then the PREVIOUS claim's id for each next one.")
	return nil
}
