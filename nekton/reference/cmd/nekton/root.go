package main

import (
	"fmt"
	"sort"

	"kton.dev/nekton/registry"
)

// The root nekton on the write path (#213). Everything here runs only when the caller writes into a
// store with its own key (`init`, or `--add`); mirror, sync and `add` of signed envelopes never create
// or extend a root - a kernel does not sign on ingest.

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
	id, err := r.CreateRoot(priv, by, when)
	if err != nil {
		return err
	}
	fmt.Printf("root %s\n", id)
	fmt.Printf("  claims written here without --scope chain under it; new subnektons are registered in it\n")
	return nil
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
