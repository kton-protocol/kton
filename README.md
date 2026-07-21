# kton

**kton** is a content-addressed substrate for verifiable science: it records **how a result was
produced** (the **plankton** layer) and **who vouched for it** (the **nekton** layer) as small, signed,
content-addressed records anyone can verify - no central server, no shared database, no blockchain. A
thin reference cockpit, also called **kton**, conducts both and reimplements neither. This repository is
the substrate and its Go reference implementation.

plankton connects **files** (identified by content hash and/or id) through **fotons** (transformations
with input files, output files, and a protocol); nekton records signed **claims** about them. The two
layers are inert and compose by hash.

> **Charter.** kton was extracted **clean-room** from the documented requirements of a pharmacometrics
> modeling workbench - derived from the idea and its observable formats, **not ported from any cockpit's
> source code** - so it can stand as an **independent substrate**. Cockpits (a workbench, a CLI, a web
> client, a paper) use it as a communication, verification, and exploration layer; the dependency points
> **cockpit → kton**, never the reverse. See [`docs/charter.md`](docs/charter.md).

plankton is the drifting foundational layer - the tiny particles that make fotons usable for the biggest
animals. **We feed the whales:** big pharma, regulators, large analyses, and AI thrive on a dense,
verifiable supply of files and transformations, which the substrate produces and connects at the base of
the food chain. It is deliberately **independent of any single [cockpit](#relationship-to-cockpits)** - a
cockpit navigates the substrate; it is not the substrate.

## Two layers, one substrate

plankton is one half of an inert two-layer substrate:

- **plankton** records **reproducible results** - a foton is `inputs → protocol(+environment)
  → outputs`, verified by re-run / hash.
- **nekton** records **attestable statements** - signed *claims* about those results (reviews,
  sign-offs, provenance, votes), rendered as nanopublications.

The dividing invariant: a machine can **verify** it (re-run / hash) → plankton; a person can
only **vouch for** it (a signature) → nekton. Dependency is one-way: **nekton → plankton**,
never the reverse. A reference cockpit, **kton**, conducts both and reimplements neither -
delete kton and every operation still runs via the protocols directly. This repo is plankton
(the results layer); nekton lives alongside it in [`nekton/`](nekton/), kton is a sibling repo.

Positioning is **composition, not invention**: plankton composes in-toto/DSSE + SHA-256
content-addressing; nekton composes the nanopublication / Trusty-URI model. The novelty is the
inert two-layer stance and the bridge between a statement corpus and reproducible execution -
not the primitives.

## The kernel

```
File      := { hash,            # content address (what it is)
               id,              # persistent identity (which one it is)
               metadata? }

Foton     := { inputs:   [FileRef...],     # FileRef = hash and/or id
               outputs:  [FileRef...],
               protocol: ProtocolRef }     # opaque, content-addressed

Protocol  := an opaque, content-addressed descriptor with a typed `kind`.
             plankton does NOT know how to run it. Executors are external.

Registry  := the graph that connects all Files and Fotons.
             A foton is an edge: input files -> protocol -> output files.
             The registry IS the lineage graph.
```

**No filestore.** plankton stores no bytes - a `{hash, uri}` is enough. It is the pure
metadata plane (the graph); the bytes live wherever they already are and are verified by
hash. That is the whole idea. Everything else - a filestore, a cockpit, an executor, a
transport - is external and pluggable. See [`docs/architecture.md`](docs/architecture.md).

plankton is the **counterpart to an execution API**: a *shared, explorable execution
cache*. An execution API runs things; plankton remembers what `(inputs + protocol)`
produced - across organizations. That one store gives **reuse** (cache hits dedup work
between galaxies), **tool qualification** (a cached output is a known-correct reference
to prove a tool reproduces the right result), and **provenance** (the cache, explored,
is the lineage graph). The seed corpus is the public, CC0 **DDMORE** model repository.

**Federated from day one.** There is no central registry - every org **self-hosts** its
own (a university, a pharma, a lab), public and/or private, as peers that overlay by hash.
Lineage resolves over the registries you can see, so **partial lineage is the default**:
publish only the fotons from your aggregated data onward, and a viewer without your private
registry sees that data as plain files; with it, they see back to the source. You can
always **mirror** other registries (and pin their bytes). Statements *about* results - who
brought a ray in, who confirmed it - are the separate **nekton** layer (`nekton → plankton`),
not plankton itself; see [`nekton/`](nekton/).

See [`docs/concepts.md`](docs/concepts.md), [`docs/requirements.md`](docs/requirements.md),
[`docs/prior-art.md`](docs/prior-art.md), [`docs/federation.md`](docs/federation.md),
[`docs/attestation.md`](docs/attestation.md), and [`docs/reproduction-identity.md`](docs/reproduction-identity.md).

## Why this exists

A file is *what it is* (its hash) and *which one it is* (its id). A foton records
*how one set of files became another*. A registry of fotons over a content-addressed
file store is, by construction, a complete and verifiable lineage graph - shareable
across organizational boundaries because files are recognizable by hash anywhere.

This is the FOTON / DMG idea, extracted from a modeling workbench so it
can stand, spread, and succeed on its own.

## Design commitments

- **Substrate, not application.** plankton stores and connects. It does not execute,
  render, or opine on workflow UX.
- **Protocol is opaque.** A foton's protocol is just another content-addressed thing
  with a `kind`. *How* a transformation runs lives in external **executors**, not here.
  This keeps the kernel small and keeps plankton from growing back into a cockpit.
- **Hash and/or id.** Files are referenceable by content (dedup, verification across
  galaxies) and by identity (mutable-pointer, "latest", human handles).
- **Neutral implementation.** The reference layer is built in a neutral language (**Go**, in
  [`reference/`](reference/)), not a cockpit's stack, to keep independence honest.
- **Determinism is a convention,** documented and designed-for, not enforced by the
  substrate.
- **Assemble, don't reinvent.** The plan is to **adopt** established, permissively-licensed
  standards for the hard layers - in-toto/DSSE and multihash are the working basis; Sigstore and
  W3C PROV/RO-Crate are **candidates under evaluation, not yet adopted** - to *transfer their
  trust* (security audits, regulatory/scientific credibility) instead of re-earning it.
  plankton writes only the thin kernel + domain semantics. See
  [`docs/novelty-and-build-vs-assemble.md`](docs/novelty-and-build-vs-assemble.md) and the open
  adjudication in [`docs/prior-art.md`](docs/prior-art.md).

## Relationship to cockpits

A cockpit is "a perfect way to navigate" - a rich client over a lineage graph.
plankton extracts the graph and the particles (files + fotons) so any cockpit can fly
them: a modeling workbench, a CLI, a published paper's verifiable package, or another org's tools.

```
            ┌─────────── cockpits ───────────┐
            │  cockpit   CLI   web   paper    │   <- read/write the substrate
            └────────────────┬───────────────┘
                             │
                    ┌────────▼────────┐
                    │     plankton    │   <- files + fotons + registry (this repo)
                    └────────┬────────┘
                             │
            ┌────────────────▼───────────────┐
            │  executors (external, by kind)  │   <- run protocols, produce outputs
            └─────────────────────────────────┘
```

## Status

The kernel is real. The Go reference implementation ([`reference/`](reference/)) builds and
passes tests: foton model + action key, canonical JSON, DSSE/Ed25519, an append-log registry
with hash indexes, lineage / reuse queries, federation (serve / mirror / sync), and optional
byte-pinning. The sibling **nekton** layer has its own Go reference ([`nekton/`](nekton/)),
reusing plankton's shared `core`. The spec ([`spec/`](spec/)) is **0.1 (draft)**. Cockpit spikes
- a VS Code Navigator, R/Python executors, and tool-qualification demos - live in a separate
research companion (not yet public).

See [`docs/concepts.md`](docs/concepts.md), [`docs/glossary.md`](docs/glossary.md),
and [`VISION.md`](VISION.md).

## Build

The repo is a Go **workspace** (`go.work`) tying three standard-library-only modules -
`plankton` (kernel), `nekton` (kernel), `kton` (cockpit). With **Go 1.22+** and no external
dependencies:

```sh
git clone https://github.com/kton-protocol/kton && cd plankton
( cd reference        && go build -o ../bin/plankton   ./cmd/plankton )
( cd nekton/reference && go build -o ../../bin/nekton   ./cmd/nekton  )
( cd kton/reference   && go build -o ../../bin/kton     ./cmd/kton    )
go test ./...            # from each module dir
bash scripts/check-import-direction.sh   # architecture guard
```

Man pages are embedded in each binary - `plankton man`, `nekton man`, `kton man` (roff source; pipe
to `man -l -` to render). The architecture invariants are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Specification & governance

kton is meant to be an **open standard others implement independently**, not just this codebase. The
normative specification ([`spec/`](spec/)) is being developed under the Linux Foundation / Joint
Development Foundation **Community Specification** framework - its scope, license, governance, and
contribution process live in [`community-specification/`](community-specification/). Two audiences:
**want to use it?** → the tools in this repo; **want to see it run?** → the demo (`gitmick/kton-demo`).

## License

Three regimes, by artifact type - a specification and its reference code have different licensing needs:

- **Code** (all Go sources under `reference/`, `nekton/`, `kton/`) - **Apache License 2.0**
  ([`LICENSE`](LICENSE)); the patent grant covers *this* implementation.
- **The normative specification** (`spec/`) - the **Community Specification License 1.0**, which grants
  *independent implementers* the copyright and patent terms a standard requires (an OSS or CC-BY license
  does not). The spec is being set up under the Linux Foundation / Joint Development Foundation
  **Community Specification** framework; until that lands the spec license is provisional.
- **Other, non-normative prose / documentation / man pages** - **CC BY 4.0**
  ([`LICENSE-CC-BY-4.0.txt`](LICENSE-CC-BY-4.0.txt)).

Copyright © 2026 Michael Hackl.
