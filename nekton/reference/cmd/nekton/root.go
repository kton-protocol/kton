package main

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
)

// The root nekton on the write path (#213). Everything here runs only when the caller writes into a
// store with its own key (`init`, or `--add`); mirror, sync and `add` of signed envelopes never create
// or extend a root - a kernel does not sign on ingest.

// rootName is the scope name of a store's root seed. The name is part of the seed's signed bytes,
// but two roots never collide on it: the seed also carries by and when.
const rootName = "root"

// initStore implements `nekton init --sign key.key [--by ID] [--when T] [--registry dir]`.
func initStore(args []string) error {
	var keyPath, by, when, regDir string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sign":
			i++
			keyPath = arg(args, i)
		case "--by":
			i++
			by = arg(args, i)
		case "--when":
			i++
			when = arg(args, i)
		case "--registry":
			i++
			regDir = arg(args, i)
		default:
			return fmt.Errorf("unknown argument %q - usage: nekton init --sign key.key [--by ID] [--when T] [--registry dir]", args[i])
		}
	}
	if keyPath == "" {
		return fmt.Errorf("usage: nekton init --sign key.key [--by ID] [--when T] [--registry dir]\n" +
			"  the root seed is signed by whoever creates the store")
	}
	priv, err := loadPriv(keyPath)
	if err != nil {
		return err
	}
	r, err := registry.Open(regOrDefault(regDir))
	if err != nil {
		return err
	}
	if r.Root() != "" {
		return fmt.Errorf("this store already has a root: %s", r.Root())
	}
	id, err := createRoot(r, priv, by, when)
	if err != nil {
		return err
	}
	fmt.Printf("root %s\n", id)
	fmt.Printf("  claims written here without --scope chain under it; new subnektons are registered in it\n")
	return nil
}

// createRoot signs and stores a root seed with the caller's key and records it as the store's root.
func createRoot(r *registry.Registry, priv ed25519.PrivateKey, by, when string) (string, error) {
	if by == "" {
		by = "key:" + keyidHex(priv.Public().(ed25519.PublicKey))
	}
	stamp, err := whenOr(when)
	if err != nil {
		return "", err
	}
	env, id, err := claim.SignWith(claimSpec{
		Subject:       []subjSpec{{URI: "urn:nekton:scope:" + rootName}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": rootName, "genesis": true, "by": by, "when": stamp},
	}, priv)
	if err != nil {
		return "", err
	}
	if _, _, err := r.Add(env); err != nil {
		return "", err
	}
	if err := r.SetRoot(id); err != nil {
		return "", err
	}
	return id, nil
}

// ensureRoot returns the store's root, creating it with the caller's key if the store has none yet:
// the first write into a store without `init` opens its root, on the caller's own write path.
func ensureRoot(r *registry.Registry, priv ed25519.PrivateKey, by string, msg func(string, ...any)) (string, error) {
	if id := r.Root(); id != "" {
		return id, nil
	}
	id, err := createRoot(r, priv, by, "")
	if err != nil {
		return "", fmt.Errorf("this store has no root yet and creating one failed: %w", err)
	}
	msg("root %s  (created: this store had none)\n", id)
	return id, nil
}

// placeInStore prepares a spec for writing into r: a claim that names no scope chains under the
// store's root, and a new seed without a parent hangs off it. A spec that names a scope, or a seed
// that names a parent, is left as the caller wrote it.
func placeInStore(r *registry.Registry, spec *claimSpec, priv ed25519.PrivateKey, msg func(string, ...any)) error {
	if spec.PredicateType == claim.ScopePredicateType {
		if _, has := spec.PredicateBody["parent"]; has {
			return nil
		}
		root, err := ensureRoot(r, priv, bodyBy(spec), msg)
		if err != nil {
			return err
		}
		spec.PredicateBody["parent"] = map[string]any{"hash": root}
		return nil
	}
	if spec.Scope != "" {
		return nil
	}
	if _, has := spec.PredicateBody["scope"]; has {
		return nil
	}
	root, err := ensureRoot(r, priv, spec.By, msg)
	if err != nil {
		return err
	}
	if spec.PredicateBody != nil {
		spec.PredicateBody["scope"] = root
		spec.PredicateBody["prev"] = r.RootHead()
	} else {
		spec.Scope, spec.Prev = root, r.RootHead()
	}
	return nil
}

func bodyBy(spec *claimSpec) string {
	by, _ := spec.PredicateBody["by"].(string)
	return by
}

// registerSubnekton appends the root entry that registers a seed this store just opened.
func registerSubnekton(r *registry.Registry, seedID string, priv ed25519.PrivateKey, by string) (string, error) {
	if by == "" {
		by = "key:" + keyidHex(priv.Public().(ed25519.PublicKey))
	}
	stamp, err := whenOr("")
	if err != nil {
		return "", err
	}
	env, id, err := claim.SignWith(claimSpec{
		Subject:   []subjSpec{{Hash: seedID}},
		Predicate: registry.RegistersPredicate,
		By:        by,
		When:      stamp,
		Scope:     r.Root(),
		Prev:      r.RootHead(),
	}, priv)
	if err != nil {
		return "", err
	}
	if _, _, err := r.Add(env); err != nil {
		return "", err
	}
	return id, nil
}

// rootReport implements `nekton verify --root [--json]`: the store's root chain from its seed to the
// last entry present, the subnektons it registers and whether each is held, and every fork. A fork is
// reported, never rejected (SPEC §11).
func rootReport(regDir string, asJSON bool) error {
	r, err := registry.Open(regOrDefault(regDir))
	if err != nil {
		return err
	}
	root := r.Root()
	if root == "" {
		return fmt.Errorf("this store has no root (run `nekton init --sign key.key`)")
	}
	heads, chainLen, _ := r.Heads(root)
	forks := r.Forks(root)
	registered := r.Registered()
	var missing []string
	for child, held := range registered {
		if !held {
			missing = append(missing, child)
		}
	}
	sort.Strings(missing)
	if asJSON {
		return printJSONOut(map[string]any{
			"root": root, "head": r.RootHead(), "heads": heads, "chainLength": chainLen,
			"unresolved": r.Unresolved(root), "forks": forks,
			"registered": len(registered), "registeredMissing": missing,
		})
	}
	fmt.Printf("root:        %s\n", root)
	fmt.Printf("chain:       %d entries, local head %s\n", chainLen, r.RootHead())
	fmt.Printf("registered:  %d subnekton(s)", len(registered))
	if len(missing) > 0 {
		fmt.Printf(", %d not held here: %v", len(missing), missing)
	}
	fmt.Println()
	if n := r.Unresolved(root); n > 0 {
		fmt.Printf("unresolved:  %d entr(y/ies) name the root but their prev is missing - something between two entries is absent\n", n)
	}
	if len(forks) == 0 {
		fmt.Printf("forks:       none\n")
	}
	for prev, ids := range forks {
		fmt.Printf("fork:        %d entries continue from %s: %v (both valid; a copy of this store wrote too)\n", len(ids), prev, ids)
	}
	return nil
}
