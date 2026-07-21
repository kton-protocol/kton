# Charter - what plankton is for

**Origin.** The idea emerged from improve.

**Mission.** A **clean-room implementation** that improve (and others) use as a
**communication, verification, and exploration layer**.

improve is the first **cockpit / consumer**, not the owner. The dependency points
**improve → plankton**, never the reverse.

## Clean room - what it means here

plankton is derived from the **idea and the documented requirements** - improve's documented specifications and its *observable export formats* - and implemented **independently in a
neutral stack**. It is **not ported from improve's source code**.

Why this discipline:
- **Neutral & shareable** - can become an open substrate / standard that any cockpit or org
  adopts (`N1`, `N2`).
- **Trust-transferable** - the same logic as assembling in-toto/Sigstore (`N8`): independence
  is what lets others trust and adopt it.
- **Independently licensable** - no entanglement with improve's code or licensing.

The practical rule:
- Reading improve's **data** (an export, a `workflow.json`, a file + its hash) - **fine**;
  that's an adapter consuming a format.
- Porting improve's **code** into the reference implementation - **no**; reimplement from the
  spec.

Honest caveat: this is *our own* idea being extracted, so "clean room" here means
**architectural neutrality and reusability**, not defending against a third party's IP claim.

## The three layers (this is how the requirements cluster)

| Layer | What improve gets from plankton | Requirements |
|-------|----------------------------------|--------------|
| **Communication** | share, publish, federate, mirror - across steps, repos, and organisations | F6 export/import, **F9** adapters/publish, **F11** WebRay/papers, **F13** federation + mirroring, attestation **authorship** (F12.1) |
| **Verification** | prove a tool produced the correct result; prove a ray is what it claims | **F7** qualification, **reproduction-identity** (L0/L1/L2), **F12** **confirmation** attestations + digital signatures |
| **Exploration** | see where data came from and what else was done with it | **F5** lineage graph, **F10** discovery / alternative scenarios, **F1.2** metadata plane |

All three run on a two-layer substrate - **plankton** records reproducible *fotons* (files
`{hash, uri, id?}` → protocol(+env) → files, by hash), and **nekton** records signed *claims*
about those results (attestations: authorship, confirmation, qualification), rendered as
nanopublications and federated independently. A third component, **kton**, is a reference
cockpit (a shell CLI) that conducts both but reimplements neither - delete kton and every
operation still runs via the protocols directly. The dividing invariant: machine-verifiable
(re-run / hash) → plankton; human-vouched (signature) → nekton. So the **Verification** and the
confirmation/qualification parts of the table above are the **nekton** layer (see
[../nekton/spec/SPEC.md](../nekton/spec/SPEC.md) and [attestation.md](attestation.md)), not the
plankton kernel; plankton records only fotons. The layers are *uses*, not separate systems.

## Why this shape survives (the edge is structural, not technical)

The combination is assembled from existing parts (see `novelty-and-build-vs-assemble.md`), so the
durable edge is **not** technical novelty - it is that this shape can **live without central funding
or a server**. A registry of `{hash, uri}` + signed fotons costs nothing to *persist*: it lives in
each participant's own repo and overlays by hash, with no hub to keep alive. That is the deliberate
counter to how comparable efforts die - a central, funded service (a converter stack, a hosted
repository) needs money and maintenance over years, and when the funding ends the artifact
disperses; the substrate outlives it only if no one had to keep a server running. plankton's
non-execution, no-filestore, federated design *is* that survivability property: there is almost
nothing to operate, so there is almost nothing to defund. (Governance - protecting the trademark and
the spec - is handled by a lean neutral steward, not by operating infrastructure.)

## Non-goals (what plankton deliberately is **not**)

- **Not an execution engine** - executors run protocols; plankton records and connects.
- **Not a filestore** - `{hash, uri}` is enough; bytes live elsewhere (pinning optional).
- **Not a UI / cockpit** - improve (and others) provide that.
- **Not a replacement for improve** - it is the layer improve communicates, verifies, and
  explores *through*.

## One-sentence form

> plankton is a clean-room, content-addressed lineage substrate - extracted from improve's
> own DMG idea - that gives improve (and any other cockpit) a neutral, federated,
> trust-bearing layer to **communicate**, **verify**, and **explore** scientific work.
