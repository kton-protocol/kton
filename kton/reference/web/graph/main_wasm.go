//go:build js && wasm

// The browser entry point: exposes plktBuildGraph(unionJSON, keysJSON) -> graphJSON to JavaScript.
// This is the WASM-clean kernel (plankton/core: canonicalization + Ed25519/DSSE verification)
// running IN THE BROWSER - no server, no native binary. The page fetches the content-addressed
// union, hands it here, and gets back a verified provenance/review graph to draw.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"syscall/js"
)

// streamHasher backs the incremental sha256 the lens uses to VERIFY a large file's bytes without
// holding the whole file in memory: WebCrypto's subtle.digest cannot stream, so a >512 KB file could
// only get a partial-preview badge. With plktSha256Init/Update/Final the lens feeds the fetch stream
// chunk-by-chunk and confirms the recorded hash for ANY size in O(1) memory (cold-session finding).
// One hasher: the lens hashes one file at a time (init resets it), so no concurrent-stream handle is
// needed.
var streamHasher hash.Hash

func sha256Init(_ js.Value, _ []js.Value) any {
	streamHasher = sha256.New()
	return nil
}

func sha256Update(_ js.Value, args []js.Value) any {
	if streamHasher == nil || len(args) < 1 {
		return false
	}
	buf := make([]byte, args[0].Length()) // a Uint8Array chunk
	js.CopyBytesToGo(buf, args[0])
	streamHasher.Write(buf)
	return true
}

func sha256Final(_ js.Value, _ []js.Value) any {
	if streamHasher == nil {
		return ""
	}
	sum := streamHasher.Sum(nil)
	streamHasher = nil
	return hex.EncodeToString(sum)
}

func buildGraph(_ js.Value, args []js.Value) any {
	union, keys, names := "", "{}", "{}"
	if len(args) > 0 {
		union = args[0].String()
	}
	if len(args) > 1 {
		keys = args[1].String()
	}
	if len(args) > 2 {
		names = args[2].String()
	}
	out, err := BuildGraph(union, keys, names)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return out
}

func main() {
	js.Global().Set("plktBuildGraph", js.FuncOf(buildGraph))
	// streaming sha256 for large-file verify (the lens feeds a fetch stream in chunks)
	js.Global().Set("plktSha256Init", js.FuncOf(sha256Init))
	js.Global().Set("plktSha256Update", js.FuncOf(sha256Update))
	js.Global().Set("plktSha256Final", js.FuncOf(sha256Final))
	select {} // keep the module alive so the exported func stays callable
}
