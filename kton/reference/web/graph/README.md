# graph.wasm - the kernel in the browser

`plankton/core` compiled for `js/wasm`: canonicalization, foton ids, DSSE/Ed25519 verification and
claim assembly, running in a page with no server and no native binary. A cockpit that needs to
*verify* rather than *display* records uses this instead of reimplementing the rules in JavaScript -
the reimplementation is the thing the split exists to prevent.

Same code both ways: `main_native.go` (`!js`) is a CLI harness over the identical `BuildGraph`, so
`go test ./...` and `go run ./web/graph union.json keys.json` exercise what the browser gets.

## Build

```sh
cd kton/reference
GOOS=js GOARCH=wasm go build -trimpath -o graph.wasm ./web/graph
```

**`-trimpath` is required, not a nicety.** Without it the binary embeds the absolute path of the
checkout it was built from - measured on this tree: 8 source paths, and two builds of the same commit
from two directories differ from byte 42 on. With it, the two builds are byte-identical. For a
project whose claim is verifiability, a shipped artifact must hash the same for everyone who builds
it from the same source.

Byte-identity additionally requires the **same Go version**; the toolchain is an input like any
other. The release records the one it used in `graph.wasm.buildinfo`.

## Loading it

`wasm_exec.js` is Go's own loader shim and is **toolchain-specific** - a copy from a different Go
version can fail at instantiation. Take it from the toolchain that built your `.wasm`:

```sh
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .   # Go <= 1.23
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js"  .   # Go >= 1.24
```

The release ships the matching pair, so a consumer downloading both is never mismatched.

```html
<script src="wasm_exec.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("graph.wasm"), go.importObject)
    .then(r => go.run(r.instance));   // resolves when the module exits; the globals appear before that
</script>
```

## What it exports

Nine globals on `window`, set by `main()` in `main_wasm.go`. Each returns `{error: "..."}` on
failure rather than failing silently.

| global | signature | purpose |
|---|---|---|
| `plktBuildGraph` | `(unionJSON, keysJSON?, namesJSON?) -> graphJSON` | verified provenance/review graph from a content-addressed union |
| `plktBuildScope` | `(unionJSON, scopeId) -> scopeJSON` | the §7.4 chain: order, head(s), gaps, grammar verdict |
| `plktVerify` | `(envelopeJSON, pubHex) -> verifyJSON` | check one record against one key before taking it in |
| `plktSha256Init` | `() -> null` | begin a streaming hash (resets the one hasher) |
| `plktSha256Update` | `(Uint8Array) -> bool` | feed a chunk |
| `plktSha256Final` | `() -> hex` | finish and return the digest |
| `plktBuildClaim` | `(specJSON) -> {payloadB64, ...}` | canonicalize and frame a claim for signing |
| `plktSealClaim` | `(payloadB64, sigB64, pubHex) -> envelope` | reassemble the signed DSSE envelope |
| `plktKeyIRI` | `(pubHex) -> {iri}` | the key's IRI (`kton.dev/o/<hash>`) |

The streaming hash exists because WebCrypto's `subtle.digest` cannot stream: without it a file over
~512 KB could only get a partial-preview badge. Feeding a fetch stream chunk-by-chunk confirms the
recorded hash at any size in constant memory. It is a **single** hasher - the lens verifies one file
at a time, and `Init` resets it - so do not interleave two streams through it.

The signing split is deliberate: the private key stays in WebCrypto and never enters Go. The module
only ever receives a public key and a finished signature.

### Reading a scope

`plktBuildScope` returns the chain of one scope: `members` in chain order, `heads` (each with the
ordered `path` it commits to), `defects`, and a `verdict`. Two distinctions in that output are load-
bearing and must not be collapsed in the UI:

- **`gap` vs `defect`.** A head's `gap` names a `prev` these records do not resolve. Ingest is
  monotone (§7.4, Clause 11), so the missing link may simply live in another source - present it as
  *incomplete*, never as invalid. A `defect` is a grammar violation intrinsic to the claim; no
  further source repairs it.
- **`verdict.branched` is not a failure.** Several heads is a legal state, and a branched scope can
  still be `sealable`. What a seal over a branched scope *means* is consumer policy that §7.4
  deliberately leaves open; the module reports structure and prescribes no remedy.

Membership here is structural. A record is read into the scope because it says it belongs and its
id derives from its own envelope - not because anyone verified who signed it. For that, pass the
same union through `plktBuildGraph` with a key map.

Natively, the same read is `go run ./web/graph -scope <scope-id> union.json`, which is how it is
diffed against `nekton head`.

### Verifying one record

`plktVerify` is the check before taking in a foreign entry: `{ok, keyid, declaredKeyid,
keyidMismatch, kind, claimId|fotonId, statement}`.

- **`keyid` is the key that actually verified.** The envelope's own keyid is not covered by the
  signature and can be forged, so it is returned separately as `declaredKeyid` and a disagreement
  is flagged as `keyidMismatch` (SPEC §8). Never present a declared keyid as an identity.
- **Every signature is tried**, not just the first: a co-signed envelope `[foreign, ours]` verifies
  for us and is attributed to our key.
- **The id is re-derived** from the payload, under the rule that governs the payload - `claimId` for
  a claim or seed, `fotonId` for a foton (a hash of the covered projection, not of the payload). Only
  the applicable field is set, so a caller cannot key on the wrong one.
- **A failed verify is a verdict, not an error.** `ok:false` means this key did not sign it; an error
  return means the input is not a record at all. `claimId` is still reported on `ok:false` so a
  caller knows *which* record failed.

## Verifying what you downloaded

```sh
sha256sum -c graph.wasm.sha256
```

`graph.wasm.buildinfo` carries the Go version, the exact build command and the source commit - enough
to re-derive the hash yourself rather than trusting the release.
