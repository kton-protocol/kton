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
	"kton.dev/plankton/core"
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
	addFlag, printID := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add":
			addFlag = true
		case "--print-id":
			printID = true
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
			// Any dash-prefixed token, not just "--". `-x` fell through to the positional branch and
			// became the scope NAME, and a scope name is identity: it goes into the seed's canonical
			// bytes and therefore into the scope id every scoped claim names.
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag %q - `nekton seed` takes flags --sign, --by, --parent, "+
					"--when, --add, --registry, --print-id and -o", args[i])
			}
			// LAST-WINS is how a scope silently becomes a different scope. `nekton seed sc -x v`
			// opened the scope "v", not "sc", because the second positional overwrote the first -
			// and every claim in it then named an id nobody intended. Same defect as #45, where
			// `templates` read any positional as a template name.
			if name != "" {
				return fmt.Errorf("`nekton seed` takes ONE scope name, got %q and %q - the name is "+
					"part of the scope id, so the wrong one opens a different scope", name, args[i])
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
		// `parent` is a Ref (nekton SPEC §7.4): {hash?, uri?}. NOT the subject shape,
		// {"digest":{"sha256":...}} - the two look interchangeable and are not. claim.Ref does not
		// read `digest`, so emitting it signs a parent nothing can resolve into a permanent claim id.
		if h, ok := core.NormalizeContentHash(parent); ok {
			body["parent"] = map[string]any{"hash": h}
		} else if strings.Contains(parent, ":") && !strings.HasPrefix(parent, "sha256:") {
			body["parent"] = map[string]any{"uri": parent}
		} else {
			return fmt.Errorf("--parent %q is neither a content hash nor a URI - a parent scope is named\n"+
				"  by its scope id (sha256:<64 hex>) or by a URI", parent)
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
	msg := humanOut(printID)
	msg("seed scope %q", name)
	if parent != "" {
		msg(" (parent %s)", parent)
	}
	msg("\n")
	// signClaim prints "claim <id> ..." - that <id> IS the scope id to pass as --scope. Under
	// --print-id it is the only thing on stdout, so `SCOPE=$(nekton seed x --sign k --print-id)`.
	if err := signClaim(spec, priv, out, addFlag, regDir, printID); err != nil {
		return err
	}
	msg("  ^ this claim id is the SCOPE id.\n")
	msg("    --scope <thisId> on EVERY claim in the scope (it never changes).\n")
	msg("    --prev  = this id for the FIRST claim, then the PREVIOUS claim's id for each next one.\n")
	return nil
}
