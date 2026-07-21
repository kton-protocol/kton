# reference/ - Go reference implementation (Phase 0)

The neutral-language kernel from `../spec/SPEC.md`. **Go, pure standard library** (no
dependencies): `crypto/sha256`, `crypto/ed25519`, `encoding/json` give content addressing,
DSSE verification, and canonical JSON with zero third-party code. No bytes are stored - this
is the metadata plane only.

Chosen Go for a neutral, ubiquitous, self-hostable substrate (the adopted ecosystem -
Sigstore, in-toto, OCI, multihash - is Go-native; static single binaries make self-hosting
trivial). See `../docs/novelty-and-build-vs-assemble.md`.

## Layout

This module is the **clean kernel**: pure standard library, **no `net/http`, no ports** - it
compiles to WebAssembly. Everything that opens a port (federation over the network, Rekor
anchoring) lives in the separate **kton cockpit** module (`../kton/`), which imports this one.

- `core/` - `FileRef`, `Foton`, `Protocol`, content addressing, canonical JSON, foton id +
  action key, in-toto `Statement` / DSSE `Envelope` + Ed25519 verify.
- `registry/` - the metadata plane: an **append-only log** of signed fotons, indexed by
  output/input/action hash; producers (lineage), discovery (uses), reuse (action key), and a
  `sync` feed by sequence cursor.
- `blobstore/` - an **optional** content-addressed byte store used only for pinning. The
  kernel/registry stores no bytes; this is a separate, opt-in backend (spec §6.1/§10). Pure
  filesystem, no network.
- `cmd/plankton/` - the kernel CLI. Local **`mirror <dir>`** (overlay a peer registry by hash,
  no network) stays here - it is pure federation. **Network** federation (`serve`, mirror a
  URL), transparency-log **`anchor`**, and byte **`pin`/`blob`** are in `kton` (`../kton/`).
- `testdata/` - frozen conformance vectors copied from the spike (`../spike/`). Also consumed by
  the kton federation tests (single source of truth, no duplication).

## Build & test

```
go build ./...
go test ./...        # verifies against the spike's real signed vectors
go build -o plankton ./cmd/plankton
```

The tests prove **cross-implementation interop**: this Go code reproduces the Python spike's
`protocol.ref` (canonical-JSON hashing) byte-for-byte and verifies the spike's DSSE
signatures - two independent implementations agreeing via the spec + vectors.

## CLI

```
plankton verify <envelope.dsse.json> <pubkey.hex>   # verify a DSSE attestation
plankton add    <envelope.dsse.json>                # ingest a signed foton
plankton producer <sha256:...>                      # who produced this file (lineage join)
plankton uses     <sha256:...>                      # what consumed it (discovery)
plankton reuse  <foton.statement.json>              # action key + cache-hit check
plankton lineage <sha256:...>                       # walk producers backwards
plankton hash <file>                                # content-address a file
plankton mirror <local-registry-dir>                # overlay a peer registry by hash (local, no network)
# PLANKTON_DIR sets the registry directory (default ./plankton-data)
```

### Federation - local (kernel) vs network (kton)

The kernel federates **locally**: `plankton mirror <dir>` reads a peer registry off the
filesystem and overlays it by hash - no server, no port. This is the zero-ceremony path for
cross-machine-less sharing (e.g. two working directories on one host).

```
PLANKTON_DIR=A plankton add foton.dsse.json
PLANKTON_DIR=B plankton mirror ./A                 # B overlays A's metadata, no network
PLANKTON_DIR=B plankton producer <hash>            # B now resolves lineage locally
```

**Network** federation is a cockpit concern - see `../kton/`:

```
PLANKTON_DIR=A kton serve plankton :8799           # A serves its graph over HTTP
PLANKTON_DIR=B kton mirror plankton http://A:8799  # B pulls A's metadata over the network
PLANKTON_DIR=B kton mirror plankton --pin http://A # …and pins the verified bytes
PLANKTON_DIR=B kton pin input.csv                  # pin bytes locally (optional blobstore)
```

Mirrored envelopes (local or network) keep their **original signatures** and re-verify against
the original author key - you trust the signature, not the host. Re-mirroring is idempotent
(set reconciliation of an append-only, content-addressed log). Pinned bytes are **verified
against their hash** on fetch and read; a mirror that pinned is itself a byte source. Pinning
lives in the optional `blobstore/` - the kernel still stores no bytes.

## Scope (Phase 0 + Phase 1)

In: the kernel data model, canonical hashing, action key, DSSE verify, the four hash indexes,
lineage/discovery/reuse queries, a CLI (Phase 0); the **HTTP federation API + `sync` +
mirroring** (Phase 1). Out (later phases): **byte pinning** during mirror, Sigstore-keyless /
transparency-log identity, a real KV/LSM backend, structured executors and adapters. Per
`../spec/SPEC.md` §10, execution / byte storage / UI are never the kernel.

## Known v0 limitations

- Canonical JSON implements RFC 8785 / JCS: ECMAScript number formatting, lowercase `\uXXXX`
  escapes, and rejection of duplicate member names, non-double-representable integers, and invalid
  UTF-8 - verified against the conformance vectors. (Lone-surrogate handling is the one remaining
  strict-I-JSON edge; see the spec's §5.3 limitation note.)
- Registry persistence is a directory of envelope files with indexes rebuilt on load
  (Phase 0 simplicity); a real KV/LSM backend comes with the scale phase.
