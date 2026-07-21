# kton - the cockpit that conducts plankton + nekton

`kton` is the reference **cockpit**. It orchestrates the two kernels - plankton (reproducible
fotons) and nekton (signed claims) - but **reimplements nothing**. Every operation is a call
into a kernel package; delete `kton` and each operation is still runnable directly.

## Why it exists - the clean-kernel boundary

The kernels must stay minimal enough to compile to **WebAssembly**: no `net/http`, no ports.
So everything that opens a socket or reaches the network is kept *out* of them and lives here:

- **network federation** - `serve` (the HTTP federation API) and mirroring a **URL** peer;
- **transparency-log anchoring** - Rekor (`anchor`), via the `sigstore/` package;
- **byte pinning** - the optional `blobstore` (`pin`/`blob`), used to re-serve verified bytes.

Pure, local federation stays in the kernels: `plankton mirror <dir>` / `nekton mirror <dir>`
overlay a peer registry off the filesystem by hash - no server, no port. `kton mirror` adds the
**network** peer (and can also read a local dir, as the federation console).

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
kton serve  plankton [addr]              serve the plankton federation API (default :8787)
kton serve  nekton   [addr]              serve the nekton   federation API (default :8788)
kton mirror plankton <peer> [--pin]      pull+persist a peer plankton registry (URL or local dir)
kton mirror nekton   <peer>              pull+persist a peer nekton   registry (URL or local dir)
kton anchor <envelope.dsse.json> <pubkey.hex>   anchor a signed record in Rekor
kton pin    <file>                       pin a file's bytes into the plankton blob store
kton blob   <sha256:...>                 is this content pinned locally?

env: PLANKTON_DIR (default ./plankton-data), NEKTON_DIR (default ./nekton-data)
```

## Build & test

```
go build -o kton ./cmd/kton
go test ./...     # federation tests reuse the plankton kernel's frozen vectors
```
