# Complexity & a scalable reference implementation

The big question: **how complex is the protocol, and how hard is a scalable reference
implementation?** Short answer: the kernel is small and *keeps shrinking* as we push work
out (normalization → fotons; bytes → external uris). The complexity that remains is
concentrated in a few must-be-exact spec details and at the *edges* (executors, adapters,
federation trust) - a healthy distribution: **small trusted core, complexity at the
edges.**

## What is in the kernel (and what is deliberately out)

**In - the whole protocol:**
- `FileRef = { hash, uri?, id? }` - addressed by hash, located by uri, optionally
  identified by id. **No bytes.**
- `Foton = { id, inputs[FileRef], outputs[FileRef], protocol{ref,kind} }`
  - append-only, content-addressed. (**No `attestations[]` field** - signed claims live in
  the separate **nekton** layer, keyed by the foton's subject hash.)
- A small set of **indexes** (below).
- A **query** surface: lineage, discovery, reuse-check, ref-resolve.

**The second layer - nekton (not the plankton kernel):**
- **Attestations / claims**: signed statements attached to fotons/files/rays by subject hash
  (authorship, confirmation, canonical-hash claim, qualification verdict). This is **nekton**,
  a parallel registry that federates independently and depends on plankton, never the reverse
  ([../nekton/spec/SPEC.md](../nekton/spec/SPEC.md), [attestation.md](attestation.md)). nekton
  stores and verifies signatures; it does not compute the claims. A cockpit (**kton**) conducts
  both layers but reimplements neither - delete kton and both protocols still run directly.

**Out - not the substrate's job:**
- **A filestore.** Bytes live elsewhere; `{hash, uri}` is enough. Pinning/archival is an
  *optional, pluggable* backend.
- **Executors** (run protocols, by kind) - external.
- **Adapters** (harvest fotons from Make/Snakemake/…) - external.
- **Normalization & comparison logic** - these are *fotons*; their criteria are *input
  files*. Not kernel code.
- **Cockpits / UI** - external (a modeling workbench is one).

That's roughly **four bounded plankton modules**: blob-*reference* model, foton log, indexes,
query - plus **signatures/claims in the nekton layer** alongside. Everything heavy is outside.

## No filestore: pure metadata plane

The single biggest simplification. plankton is the **metadata plane** only:

- **Identity & integrity** come from the hash; **location** from the uri; **verification**
  from re-hashing fetched bytes. You trust the hash, not the host.
- **Lineage, dedup, discovery, equivalence-by-hash, federation** all work with **zero
  bytes stored** - they operate on the graph.
- **Availability** (can I actually fetch the bytes?) is a *separate* property, required
  only to **re-run** a foton (re-execution / qualification). This is exactly the foton
  completeness gradient (F9.4) and the DDMORE "reference-only vs runnable" gate.
- **Federation is cheap:** sharing a subgraph moves kilobytes of metadata; bytes are
  fetched on demand from whatever uri, verified by hash ("build without the bytes").

This is the lakeFS "metadata over immutable objects" / Bazel "build without the bytes"
architecture taken to its end: we ship *only* the metadata.

**Overlay, don't own.** The uri may point anywhere the bytes already live and are already
governed - S3, an enterprise content/quality system (Documentum, Veeva), a cockpit (a modeling workbench),
SVN, sometimes git. plankton **owns none of them** and learns none of their protocols: it records
`{hash, uri}` and verifies by re-hashing whatever a *consumer* fetched. There are deliberately **no
per-store adapters in plankton** - resolving a uri, fetching, pinning (a one-command call) and
reading are *external / cockpit* concerns. The power is in **not** having the adapters: plankton
works over any store, present or future, precisely because it never learns to read one. This is
also why no off-the-shelf system can simply be adopted in its place - git-annex/DataLad own a git
repo, IPFS owns its network, a platform owns its hub; plankton overlays governed stores it does
**not** control, by hash.

## Content-addressing makes neutrality structural

A correction is a **new hash**, never an overwrite - content-addressing forbids mutation. So a
cleaned/reviewed output and the original **coexist as parallel offers** by construction; the
registry is physically incapable of declaring "this version supersedes that one". *"We do not
judge"* is therefore not a policy the kernel must enforce - it is a property of the data model.
Deciding which of several parallel versions is *right* (read the code, see which work was built on
which, run a compare foton, render a dashboard) is a **consumer/cockpit** act, never the
substrate's.

## The indexes (this is what must scale)

Bytes are the easy part (they're external). The graph is the substrate, and it's almost
entirely **hash-keyed lookups**:

| Index | Answers | Cost |
|------|---------|------|
| input-hash → fotons | discovery / "what else used X" / alternative scenarios | O(1) KV |
| action-key → fotons | reuse (`key = hash(canonical(inputs) + protocol)`) | O(1) KV |
| output-hash → fotons | convergence / cross-tool equivalence | O(1) KV |
| id → version history | resolve mutable pointers | O(1) KV |
| edge adjacency | lineage walk (bounded subgraph) | O(subgraph) |

Append-only + content-addressed means: trivial replication and caching (records are
immutable, name = hash), CDN-friendly, and **multi-master for free** (the same foton has
the same hash everywhere → no merge conflicts, just set union). Lineage traversal is the
only non-O(1) operation and it's bounded per query (paginate deep ancestries).

So the metadata plane scales like an **LSM/KV or document store sharded by hash prefix** -
to billions of fotons without exotic infrastructure. No graph database is *required* for
the kernel (one is a nice cockpit-side option for rich queries).

## Where the real complexity is (small in size, high in care)

Not volume - precision. These few things must be *exactly* right because they determine
cross-org hash agreement (requirement N6):

1. **Canonical serialization of a foton record** - sorted keys, canonical CBOR/JSON, so
   the same foton hashes identically in every implementation.
2. **Hash agility (multihash)** - easy to add now, painful to change later.
3. **The action-key definition** - what exactly goes into `hash(canonical(inputs) +
   protocol)`. Get this stable and reuse/qualification "just work."
4. **The protocol-kind registry** - the vocabulary of `kind` values and what each
   promises.

Genuinely hard but **deferrable** (start single-org): **federation trust** (verify-by-
re-execution vs attest-by-signature), and **GC vs immutable retention**.

## Reference implementation: sizing & phasing

Because we are **not** building a storage system (the thing that makes DVC/lakeFS/
Pachyderm large), a credible reference impl is small. Neutral language (Go or Rust):
single static binary, embedded store.

- **Phase 0 - kernel, single node.** FileRef + foton model; canonical serialization +
  hashing; embedded KV/SQLite for the foton log + the 4 hash indexes; a CLI + a thin
  HTTP/gRPC API: `record-foton`, `resolve`, `lineage`, `uses <hash>`, `find-reuse
  <inputs+protocol>`. *No bytes, no execution.* Order of **a few thousand LOC**;
  weeks, not months.
- **Phase 1 - trust & transport.** The **nekton** layer: signatures/attestations (minisign or
  sigstore); canonical-hash & verdict claims ([../nekton/spec/SPEC.md](../nekton/spec/SPEC.md)).
  Plus subgraph **export/import** (metadata + uri refs) on the plankton side.
- **Phase 2 - scale & federation.** Shard indexes by hash prefix; replication (set-union
  of immutable records); optional **pin/archival** backend for retention; federation
  trust policy.
- **Orthogonal, additive, any time:** executors (per kind), adapters (per tool), cockpit
  integrations. None touch the kernel.

## Honest risks

- Canonical encoding bugs → silent cross-org hash mismatch (mitigate: conformance test
  vectors from day one).
- uri rot → lineage survives, re-runnability doesn't (mitigate: optional pinning;
  completeness gradient is explicit about this).
- kind-registry sprawl → comparability erodes (mitigate: small curated vocabulary).
- Federation trust is the real research problem - keep it out of Phase 0.

## Bottom line

The protocol is **small and stable**; the recursion (normalization = foton) and the
no-filestore decision keep it from growing. A working, scalable reference implementation
is a **metadata/graph service of a few thousand lines**, because the two things that make
this class of system big - *storage* and *execution* - are both deliberately outside the
kernel.
