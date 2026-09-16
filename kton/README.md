# kton - the cockpit that conducts plankton + nekton

`kton` is the reference **cockpit**. It orchestrates the two kernels - plankton (reproducible
fotons) and nekton (signed claims) - but **reimplements nothing**. Every operation is a call
into a kernel package; delete `kton` and each operation is still runnable directly.

## Why it exists - the clean-kernel boundary

The kernels must stay minimal enough to compile to **WebAssembly**: no `net/http`, no ports.
So everything that opens a socket or reaches the network is kept *out* of them and lives here:

- **transparency-log anchoring** - Rekor (`anchor`), via the `sigstore/` package;
- **locator dereferencing** - `fetch`: resolve content over HTTP(S) via signed `located-at` claims,
  verify the bytes against their hash, and pin them.

Network **federation** is in neither: `serve` went in #83 and the HTTP federation client in #101 -
the latter had no caller anywhere. §12 fixes the queries and the wire form and leaves the transport
unspecified, and `plankton records --json --since N` answers `sync(since)` on stdout, which is what
a cockpit reads. Local overlay-by-hash federation stays in the kernels: `plankton mirror <dir>` /
`nekton mirror <dir>` read a peer registry off the filesystem - no server, no port.

`pin`/`blob` moved to plankton (#102): pinning needs no address, only a hash. The spellings here
still work and print a deprecation note.

## Dependency direction

```
kton ─▶ plankton      (core, registry, blobstore)
kton ─▶ nekton        (claim, registry)
```

Nothing depends on `kton`; the kernels never import it. The `federation/` and `sigstore/`
packages live in *this* module (they need `net/http`), importing the plankton kernel downward.
CI enforces all of this - see `../scripts/check-import-direction.sh`.

## CLI

```
kton mirror plankton <peer> [--pin]      pull+persist a peer plankton registry (URL or local dir)
kton mirror nekton   <peer>              pull+persist a peer nekton   registry (URL or local dir)
kton anchor <envelope.dsse.json> <pubkey.hex>   anchor a signed record in Rekor
kton pin    <file>                       pin a file's bytes into the plankton blob store
kton blob   <sha256:...>                 is this content pinned locally?

env: PLANKTON_DIR (default ./plankton-data), NEKTON_DIR (default ./nekton-data)
```

## Build & test

The module root is `kton/reference/`, not this directory - the commands below assume you are in it:

```
cd reference
go build -o kton ./cmd/kton
go test ./...
```
