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
		fmt.Fprintln(os.Stderr, "usage: graph <union.json> [keys.json]")
		os.Exit(2)
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
