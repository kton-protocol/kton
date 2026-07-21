# Glossary

Standalone vocabulary for plankton. Terms inherited from the founding vision are
noted; plankton's definitions are deliberately decoupled from any cockpit.

**plankton** - the registry substrate that records **reproducible results** (fotons):
content-addressed files + fotons + the graph connecting them. The base of the food chain;
the particles that feed the whales. plankton records *only* fotons; signed claims *about*
them are the [[nekton]] layer.

**nekton** - the second substrate layer: it records **attestable statements** - signed
[[attestation|claims]] about plankton results (authorship, confirmation, qualification),
ontology-agnostic and rendered as nanopublications, federated independently by subject hash.
Dividing invariant: machine-verifiable (re-run/hash) → plankton; human-vouched (signature) →
nekton. Depends on plankton, never the reverse. See `../nekton/spec/SPEC.md` and
[[attestation]].

**kton** - the reference **cockpit**: a shell CLI that conducts both plankton and nekton but
**reimplements nothing** - delete kton and every operation still runs via the protocols
directly. The protocols never depend on cockpits - a design rule (kton is a shell, not an
importable module). CI enforces the adjacent kernel edge: plankton never imports nekton
(`scripts/check-import-direction.sh`).

**File** - an immutable blob, referenceable by content **hash** (what it is) and by
**id** (which one it is).

**Hash / content address** - a content-derived identifier (e.g. `sha256:…`). Identical
bytes hash identically anywhere, enabling dedup and cross-galaxy recognition.

**Id** - a persistent identity for a file or foton. May be a stable pointer that
resolves to different hashes over time; each version stays pinned by hash.

**FileRef** - a reference to a file by **hash and/or id**. Hash-only = exact bytes;
id-only = current target of an identity; both = pinned + verifiable. A FileRef with **no
hash** (a path only) is an **unbound slot** - a [[hole]] (input) or [[virtual output]] of a
[[potential]], bound when the potential is realized.

**Foton** - a transformation: `inputs (FileRefs) -> protocol -> outputs (FileRefs)`.
An edge in the registry. The shareable, verifiable unit. (the FOTON idea: "File Only
Transfer Over Net Steps.")

**Protocol** - an **opaque, content-addressed** descriptor with a `kind`. plankton
records it but does not run it.

**ProtocolKind** - a typed tag that tells an **executor** how to handle a protocol.

**Executor** - external runner, registered by ProtocolKind, that fulfills a protocol:
`(inputs, protocol descriptor) -> outputs`. Not part of the plankton kernel.

**Potential** - a [[foton]] with **unbound slots**: input [[hole]]s and/or [[virtual output]]s.
A template (and a [[normalizer]] is one). The kernel stores it content-addressed (it has a
stable id) but never interprets it; an [[executor]] **realizes** it. A foton with every slot
bound is the special case - re-runnable as-is.

**Hole** - an unbound *input* slot of a potential (a [[FileRef]] with a path, no hash), bound
to a concrete input at realization. A potential may have one or more.

**Virtual output** - a *declared* output slot of a potential (a [[FileRef]] with a path, no
hash). On realization the producer keeps **only** the declared virtual outputs - they are the
[[mask]] (stated positively: what the computation produces). A potential may have one or more.

**Realize / Realization** - an [[executor]] turns a [[potential]] into a concrete [[foton]]:
bind the holes to input hashes, produce the virtual outputs, keep only those. Only executors
realize; the kernel does not.

**Registry** - a **self-hosted scope** of fotons and file refs (the plankton layer;
[[attestation|claims]] live in the parallel [[nekton]] registry). Every org runs its own
(public and/or private); there is no central one. The graph you see is the **union of
accessible registries, joined by file hash**. Standalone, federated equivalent of a modeling workbench's
**DMG** (Data Manipulation Graph). See [[federation]].

**Federation** - registries as peers that overlay by hash. Lineage resolves over the union
you can access; **partial lineage is the default**.

**Lineage root** - a file (`{hash, uri}`) with no producer in any visible registry - *a
file without lineage*. Becomes connected if a registry holding its producing foton becomes
visible (**splicing**, by hash, automatic and verifiable).

**Mirror** - a pulled, persisted copy of another registry (metadata, optionally pinning
bytes), itself re-servable. Mirroring ≠ confirming. The pin/retention and uri-rot defence.

**Cockpit** - any application that reads/writes the substrate: a workbench, a CLI, a web
app, a paper's verifiable package. A cockpit is "a perfect way to navigate."

**Whale** - a large consumer of the substrate: big pharma, regulators, meta-analyses,
AI systems. plankton's purpose is to feed them abundant, verifiable transformations.

**Galaxy** - one repository/instance of organized work. Files are
recognizable across galaxies by hash.

**Ray** - a connected subgraph (path/DAG) of fotons; light travelling through the graph.
A **WebRay** is a published, citable ray (a paper). See [[attestation]].

**Attestation / Claim** - a signed statement attached to the graph by subject hash:
`{subject, predicate, by, when, why?, evidence?, signature}`. This is the [[nekton]] layer,
**not** plankton: nekton stores and verifies claims; it does not produce them. (foton = a
machine-verifiable result → plankton; claim = a human-vouched statement about one → nekton.)
See `../nekton/spec/SPEC.md` and [[attestation]].

**Authored / Confirmed** - the two core attestation predicates: *who brought a ray in*
(authored, first-party) vs *who verified it* (confirmed, third-party). Author ≠ confirmer
= GxP four-eyes.

**Identity confirmation** - an `identity-equivalent` [[nekton]] claim over a **ray-pair**:
"ray A ≡ ray B under criteria C." (The mechanical L0/L1/L2 comparison is a plankton
`kind=compare` foton; the signed *acceptance* of its verdict is this nekton claim.)
Confirmation is **ray-level, not per-foton**, because normalized identity lives at ray
endpoints. See [[reproduction-identity]].

**Determinism (as convention)** - same inputs + same protocol → same outputs. Designed
for and documented, not enforced by the substrate.

**Reproduction identity** - the equivalence relation deciding when two results count as
"the same", coarser than byte-equality: **L0** byte-identical, **L1** canonically-
identical (after normalization strips incidental fields), **L2** semantically-equivalent
(parsed results within tolerance). See [[reproduction-identity]].

**Canonical hash** - a file's hash *after* a named normalization profile (vs the raw
content hash). *What it means for reproduction* vs *what it literally is*.

**Normalization profile / Tolerance spec** - content-addressed, versioned, signed
criteria (per protocol kind + file role) that define L1/L2 equivalence. The auditable OQ
acceptance criteria.

**Normalizer** - a [[potential]] whose protocol canonicalizes its input(s) → canonical
output(s); its rules are a [[normalization profile]]. Realizing it emits a **normalization
foton** (raw → canonical), which is what makes **L1** [[reproduction identity]] a pure graph
query. One normalizer can canonicalize a whole result set in a single realization (many holes
→ many virtual outputs).

**Mask** - a [[potential]]'s [[virtual output]]s, taken as the **positive** declaration of
its identity-bearing outputs: realizing keeps only those, so everything else a run emits
(scratch dirs, stdio, logs) is dropped. The cheap complement to a [[normalizer]] - drop the
regenerable artifacts wholesale; normalize only the residual volatile-but-meaningful content.
