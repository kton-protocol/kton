//go:build !js

// Native test harness: `go run ./web/graph union.json keys.json` prints the graph JSON. Lets us
// validate the exact logic that the wasm build serves to the browser.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: graph <union.json> [keys.json] [names.json]")
		fmt.Fprintln(os.Stderr, "       graph -scope <scope-id> <union.json>")
		os.Exit(2)
	}
	// The scope read, natively. Lets the 7.4 chain view be diffed against `nekton head` on the same
	// records - the cross-check that keeps the browser and the CLI from drifting apart.
	if os.Args[1] == "-scope" {
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: graph -scope <scope-id> <union.json>")
			os.Exit(2)
		}
		union, err := os.ReadFile(os.Args[3])
		if err != nil {
			panic(err)
		}
		out, err := BuildScope(string(union), os.Args[2])
		if err != nil {
			panic(err)
		}
		fmt.Println(out)
		return
	}
	union, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	keys := []byte("{}")
	if len(os.Args) > 2 {
		if k, err := os.ReadFile(os.Args[2]); err == nil {
			keys = k
		}
	}
	names := []byte("{}")
	if len(os.Args) > 3 {
		if n, err := os.ReadFile(os.Args[3]); err == nil {
			names = n
		}
	}
	out, err := BuildGraph(string(union), string(keys), string(names))
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}
