# Federation - many registries, one graph by hash

Federated from day one. There is **no central registry**. Every organization **self-hosts**
its own - a university, a pharma, a lab each run their own plankton instance, typically a
**public** one (what they share) and a **private** one (what they keep). Registries are
**peers that overlay by hash.**

> **Both layers federate - independently.** The substrate is two layers: **plankton** (foton
> registries) and **nekton** (claim registries; see [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md)).
> Each has its **own** registry and federates the same way - by hash. A **cockpit** (e.g. kton)
> **joins them by subject hash**: a nekton claim's subject is the hash of the plankton foton/ray/file
> it vouches for, so the two overlays line up with no shared identifiers to reconcile. Everything
> below about hash-joined federation applies to each layer on its own; the attestation/confirmation
> mechanics are the **nekton** side.

This is not a bolt-on; it falls out of the kernel (files are hashes, fotons are edges over
hashes), which is why it costs almost nothing to support.

## The one mechanism: resolve producers by hash

A foton's input is a hash. Lineage is the query:

> *Does any **visible** registry hold a foton whose **output** == this hash?*

- **Yes** → lineage extends into that registry.
- **No** → the file is a **lineage root**: a `{hash, uri}` with no visible producer - *a
  file without lineage.*

So **the graph you see = the union of the registries you can access, joined by file hash.**
Partial lineage is the default state, not a feature you switch on.

## Selective publication (the aggregated-data example)

```
PRIVATE registry (university)              PUBLIC registry (university shares)
─────────────────────────────             ───────────────────────────────────
source_data ──F1──▶ cleaned ──F2──▶ AGG          AGG ──F3──▶ result
                                    │              ▲
                                    └──────────────┘  same hash(AGG)
```

The university publishes only `F3` (and onward) to its public registry. `F3`'s input is
`hash(AGG)`.

- **Viewer with the private registry** (or granted access): `hash(AGG)` resolves to `F2`'s
  output → lineage runs **back to `source_data`**.
- **Viewer without it**: `hash(AGG)` has no visible producer → AGG is a **plain file**, and
  the public graph starts at `result`. Exactly what you wanted.

No "hide lineage" operation exists - the upstream fotons simply aren't in the graph the
viewer can see. And critically: the public registry need not even *mention* the private
upstream hashes (publish *starting at* AGG), so nothing leaks.

## Splicing is automatic and verifiable

When access is later granted (or two orgs connect), the private `F2.output.hash ==` the
public `F3.input.hash` → the edges join **with cryptographic certainty**. No identifiers to
reconcile, no manual stitching - content-addressing does the join.

## Sync = set reconciliation of append-only, content-addressed records

Because fotons/files/attestations are **immutable and content-addressed**:
- Syncing two registries = **set union** of records (the same record has the same hash
  everywhere → no conflicts, CRDT-trivial; Merkle-style reconciliation to find diffs).
- A **public instance** = open read; a **private instance** = authenticated read with
  access control. Federation is "ask the registries you're allowed to, union the answers."

  That is a description of deployments, not of anything this repository ships. The reference
  implementation has a federation **client** (`kton mirror`) and **no server**: the §12 queries are
  normative, the transport is not (SPEC Annex C), and a listening socket brings authentication,
  transport security, rate limiting and request bounds with it — obligations that belong to whoever
  deploys, not to a protocol reference. Serving the §12 table is a small amount of code in any
  language, and `reference/testdata/federation/` fixes the bytes it has to produce.
- Lazy as ever: you exchange *metadata*; bytes are fetched from uris on demand, verified by
  hash.

## What a registry must expose (federation API, small)

- `has-producer(hash)` / `get-foton-by-output(hash)` - the lineage join.
- `uses(hash)` - discovery / alternative scenarios across the federation.
- `get-ray(ref)` - fetch a subgraph (a WebRay).
- `attestations(subject)` - who authored / confirmed. *(This is the **nekton** registry's endpoint,
  keyed by the plankton subject hash; see [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md).)*
- `sync(since)` - set reconciliation.
- all under **access control**; public endpoints expose only the public scope.

## Mirroring - pull, persist, re-serve

You can always **mirror** any registry you can see. Because records are content-addressed
and append-only, mirroring is just **sync (above) with persistence**:

- **Metadata mirror** - copy the fotons/files/attestations (the graph). Cheap; gives you
  offline lineage, speed, and resilience.
- **Byte pinning** - also fetch the bytes behind the uris into your own backend and add
  your store as a new uri location. This is the defence against **uri-rot** and the
  realisation of **GxP retention**: mirror + pin the public DDMORE registry and you hold a
  **durable, re-runnable qualification corpus even if DDMORE goes offline.**
- **Re-serve** - a mirror is itself a peer/cache; mirroring strengthens the whole
  federation (Nix-cache / IPFS-pin / Software-Heritage pattern).
- **Mirroring ≠ confirming.** Copied attestations keep their **original signer**; you
  vouch for nothing unless you add your *own* attestation.

Mirror scope is your choice: a single ray, a scope, or a whole public registry.

## Trust across the federation

Seeing a foreign ray ≠ trusting it. Trust is carried by **attestations** (`authored` /
`confirmed`), which are the **nekton** layer - signed claims about plankton results, keyed by
subject hash ([attestation.md](attestation.md), [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md)) -
and decided by **per-galaxy policy** (whose confirmations count). nekton only *stores and verifies*
signatures; cockpits decide whom to believe. (Sigstore/Rekor-style transparency logs fit here.)

## The privacy caveat of content-addressing

A hash can be a **confirmation oracle** for sensitive data: if content is guessable, anyone
can hash a candidate and check whether your registry references it ("did this patient record
exist here?"). Mitigations, per data class:
- publish only at a safe boundary (aggregated/anonymized), never reference raw-sensitive
  hashes in any shared scope;
- use **salted/HMAC** content addresses for sensitive files (hash with a private key →
  still dedups within a trust domain, opaque outside);
- keep sensitive scopes private and access-controlled.
This is a real design constraint, called out so it isn't discovered late.

## Prior art

- **Nix substituters / binary caches** - ask multiple caches for a hash; closest analog to
  "resolve a producer/output across instances."
- **Git remotes / DataLad siblings, git-annex** - content available from many remotes; you
  see what you can fetch; decentralized by design.
- **IPFS/IPNS** - content from any peer by CID.
- **Software Heritage** - durable fallback source archive (the pin/retention role).
- a modeling workbench's **cross-repo import** scripts - the in-house precursor, now made
  first-class and cross-org.

## Requirements

See **F13** in `requirements.md`. Federation strengthens N1 (no single host), N4 (metadata
is small, cheap to self-host and sync), and N7 (federation trust).

## Open questions

- Discovery *reach*: how does a viewer learn which registries to ask? (registry directory /
  peer list / gossip - a cockpit concern, kept out of the kernel.)
- Revocation of access vs already-synced records (you can't un-send metadata someone pulled).
- Per-record vs per-scope access control granularity.
