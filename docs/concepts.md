# Concepts & data model

The plankton kernel is four types. Everything else is a cockpit, an executor, or a
transport built on top.

> **Layer note.** plankton records **fotons** (reproducible results, by hash). Signed *claims*
> about those results - attestations, confirmations, qualification verdicts - are the separate
> **nekton** layer ([../nekton/spec/SPEC.md](../nekton/spec/SPEC.md),
> [attestation.md](attestation.md)), keyed by subject hash and federated independently. Where
> `attestations` appear below (e.g. in a registry's shape or an `environment-qualification`),
> read them as the nekton layer conducted alongside plankton by a cockpit (**kton**), not as a
> plankton kernel type. The plankton kernel proper is File / Foton / Protocol / Registry.

> **One-line framing:** plankton is the **counterpart to an execution API** - a
> *shared, explorable execution cache*. An execution API answers "run this"; plankton
> answers "has this `(inputs + protocol)` been run, by anyone, and what came out?" The
> same store powers three things: **reuse** (cache hit = skip recompute / recognize
> identical work across orgs), **tool qualification** (the cached output is a
> known-correct reference to compare a re-run against), and **provenance** (the cache,
> explored, is the lineage graph). See [requirements.md](requirements.md).

## File

A file is an immutable blob, referred to by hash and/or id - **plankton stores no
bytes**, only the reference.

```
File := {
  hash:      ContentHash,   # content address - WHAT it is (e.g. sha256:...)
  path?:     RelPath,       # RELATIVE path in the foton work tree ("raw/data.csv") - structural
  id?:       FileId,        # persistent identity - WHICH one it is
  locations?:[Uri...],      # WHERE the bytes can be fetched (hints; many possible)
  metadata?: Map            # optional: media type, size, free-form
}
```

> **Relative paths are structural; absolute paths are incidental.** Tools depend on layout
> (a control stream's `$DATA raw/x.csv`; PsN writing into `modelfit_dir1/NM_run1/`), so a
> file's *relative* path is part of the foton and its action key. The *absolute* sandbox root
> is chosen by the executor at run time and is never recorded - that keeps the same work
> identical across galaxies. The input/output sets are really **path→hash trees**.

- **hash** gives deduplication and cross-galaxy recognition. The same bytes anywhere
  produce the same hash, so identical data is recognizable even when named differently.
- **id** gives identity and human handles. An id can be a stable pointer ("the latest
  cleaned dataset") that resolves to different hashes over time, while each *version*
  remains pinned by hash.
- A `FileRef` is **a hash and/or an id**, optionally with **uri location(s)**.
  Hash-only = "exactly these bytes". Id-only = "whatever this identity currently points
  to". Both = "this identity, pinned to these bytes" (the verifiable form). The uri says
  *where to fetch*; the hash says *how to verify what you fetched* - so you trust the
  hash, not the uri.

**plankton holds no filestore.** A `{hash, uri}` is enough: the registry is pure
metadata (the graph), the bytes live wherever they already are (S3, an OCI registry, a
lab filesystem, DDMORE's download URL). This makes identity, lineage, dedup, discovery,
and hash-equality work with zero byte storage. *Availability* of the bytes is a separate
property, needed only when a foton must be **re-run** (re-execution / qualification) -
which ties to the foton completeness gradient. Long-term retention is an **optional,
pluggable pin/archival** concern (one backend choice), not part of the kernel.

## Foton

A foton is a transformation - an **edge** in the registry connecting input files to
output files via a protocol.

```
Foton := {
  id:       FotonId,
  inputs:   [FileRef...],
  outputs:  [FileRef...],
  protocol: ProtocolRef
}
```

A foton asserts: *these inputs, through this protocol, produced these outputs.* It is
the unit that travels and the unit that is verified.

The foton is also the **cache key**: looked up by the digest of `(inputs + protocol)`,
it returns the prior outputs if anyone has computed them. That single mechanism is
reuse (skip recompute), qualification (re-run and compare against the stored outputs),
and lineage (follow the edges).

> Determinism (same inputs + same protocol → same outputs) is a **convention** that
> fotons are designed for and documented against. The substrate does not enforce it.

## Protocol

The protocol connects the transformation - but plankton treats it as **opaque**.

```
Protocol := {
  ref:   ContentHash,   # the protocol descriptor is itself content-addressed
  kind:  ProtocolKind   # a typed tag that tells an executor how to handle it
}
```

- plankton **does not know how to run a protocol.** It stores the reference and the
  kind. *How* the transformation executes is the job of an external **executor**
  registered for that `kind`.
- The descriptor behind `ref` can be anything addressable: a command + environment, a
  container spec, a workflow definition, a pointer to source - the registry neither
  parses nor cares. To plankton it is just another hashed input.
- This is the wall that keeps plankton small. Execution logic lives outside; the
  substrate only records and connects.

### Environment (part of the protocol - the tool-qualification anchor)

The **execution environment** is a typed, content-addressed, extensible entity carried in the
protocol descriptor: `Environment{kind, ref, descriptor}` - kind ∈ {oci/docker-by-digest, nix,
guix, renv, apptainer, conda, **workbench-tool-instance**, …}. Because it's in the protocol, it's
in `protocol.ref` and the **action key**: *same inputs + same protocol incl. the same
environment → same outputs.* Docker-image-by-digest is one kind; it does not have to be Docker.

The environment can itself be **qualified**: an `environment-qualification` claim (a **nekton**
attestation, not a plankton foton) records its IQ/OQ. A result is trustworthy only if its
environment carries a valid qualification from a trusted party - *"executed by a tool that passed
a defined qualification."* This is the tool-qualification (TQ) anchor - distinct from the *result*
verdict (one qualifies the tool, the other the output); both verdicts live in nekton, while the
mechanical comparison behind them is a plankton `kind=compare` foton. See
[reproduction-identity.md](reproduction-identity.md), [attestation.md](attestation.md), and
[../nekton/spec/SPEC.md](../nekton/spec/SPEC.md).

### Executors (external, not part of the kernel)

An executor is anything that can fulfill protocols of a given kind: take the inputs +
the protocol descriptor, run it, and produce outputs to register. Executors are how
plankton stays a substrate instead of growing back into an application.

```
Executor:  (inputs, protocol_descriptor) -> outputs
           registered by ProtocolKind, lives outside plankton
```

## Registry (federated - there is no single one)

A registry is a **self-hosted scope** of fotons, file refs, and attestations. Every
organization runs its own - a university hosts its registry, pharma hosts theirs, a lab
hosts theirs; an org typically runs a **public** instance (what it shares) and a
**private** one (what it keeps). There is no central server; registries are **peers that
overlay by hash**.

```
Registry := {
  files:        set of FileRef     (by hash, by id, with uri locations)
  fotons:       set of Foton       (edges over FileRefs)
  attestations: set of Attestation (the nekton layer - authored / confirmed / … ;
                                    a parallel registry keyed by subject hash, not a
                                    plankton kernel set - see ../nekton/spec/SPEC.md)
}
```

- A file's **outgoing** edges (fotons that consume it) and **incoming** edge (the foton
  that produced it) give lineage: *where did this come from, and what depends on it.*
- **The graph you see is the union of the registries you can access**, joined by file
  hash. To find what produced a file, ask: *does any visible registry hold a foton whose
  output is this hash?*
  - **Yes** → lineage extends into that registry.
  - **No** → the file is a **lineage root**: a `{hash, uri}` with no visible producer - *a
    file without lineage.*
- So **partial lineage is the default, not a feature.** Publish only the fotons from your
  aggregated data onward: a viewer with your private registry sees back to the source; a
  viewer without it sees the aggregated data as plain files. When access is later granted,
  the private foton's output hash **==** the public foton's input hash, so the graphs
  **splice automatically and verifiably** - no manual stitching.
- This is the standalone, *federated* equivalent of a modeling workbench's **DMG (Data Manipulation
  Graph)** - extracted, so it belongs to no single application or host. See
  [federation.md](federation.md) and [attestation.md](attestation.md).
- A "tree" or any other view is just a projection over this graph, owned by a cockpit.

## How things get in, and how they're found

**Two write paths into the cache:**

- **Execute-then-record** - an external *executor* runs a protocol; the result is
  recorded.
- **Observe-and-publish** - an *adapter* harvests a foton from a tool that **already
  ran** (Make, Snakemake, Nextflow, CWL, Bazel, CI, shell). plankton executes nothing.
  Adapters extract at whatever granularity the source exposes.

Because of the second path, plankton absorbs lineage passively - any flow tool can
publish into it. Fotons published this way may have an **opaque/partial protocol**, so
each foton carries a **completeness level**:

```
fully-pinned + re-runnable + qualified   ← reuse + re-execution + qualification
   ↓
observed (inputs/outputs/kind known)     ← discovery + scenarios
   ↓
lineage-only (protocol opaque)           ← still addressable and explorable
```

**Discovery falls out of content-addressing.** Index fotons by their input set, and one
index answers three questions:

| Query | Meaning |
|-------|---------|
| same `(inputs + protocol)` exists | **reuse** - don't recompute |
| same inputs, *different* protocol | **alternative scenarios** - the branches |
| **equivalent** outputs, different protocol | **cross-tool equivalence** - same result |

Output addressing is what makes results comparable *across tools*. But "equivalent"
rarely means **byte-identical** - real tool outputs embed incidental content (licensee,
date, paths) and differ numerically. Equivalence is a relation coarser than byte-equality
(canonical or semantic), defined per protocol kind. See
[reproduction-identity.md](reproduction-identity.md).

**Every file and foton is globally addressable**, so a *subgraph* can be published as a
citable package (a **WebRay**) - a paper whose every step a reader can fetch, verify by
hash, and re-run (if runnable).

## What lives where

| Concern                         | plankton (substrate) | external           |
|---------------------------------|----------------------|--------------------|
| Content-addressed file storage  | ✅                   |                    |
| Foton registry / lineage graph  | ✅                   |                    |
| File & protocol refs (hash/id)  | ✅                   |                    |
| Running a protocol              |                      | executors (by kind)|
| UI, dashboards, tree explorers  |                      | cockpits           |
| Workflow orchestration / UX     |                      | cockpits           |
