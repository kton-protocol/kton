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

// seed creates + signs a scope-genesis statement and prints the scope id (its claim id), which
// scoped claims then reference via --scope. A seed carries genesis:true and no prev (SPEC §7.4).
func seed(args []string) error {
	var name, by, parent, keyPath, out, regDir string
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
	body := map[string]any{
		"scope":   name,
		"genesis": true,
		"by":      by,
		"when":    time.Now().UTC().Format(time.RFC3339),
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
