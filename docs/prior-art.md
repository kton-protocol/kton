# Prior art

What already exists that does something like plankton - so we borrow, not reinvent.
Researched 2025-2026. Two parts: **inside the workbench** (what we're extracting) and **the
world** (the landscape + the genuine white-space).

> **Note:** Anthropic's Claude
> Science (2026) independently ships per-artifact code+environment provenance + a reviewer agent
> (validating the foton/nekton primitives), but keeps it in-app, unsigned, non-portable, and
> unregulated - precisely plankton/nekton's neutral, signed, federated, GxP substrate.

## Inside the workbench - we are extracting, not inventing

The DMG already exists, in Java, owned by the workbench. plankton's job is to make it
explicit, neutral, and standalone.

- **DMG service + UI** - a Java DMG service + UI,
  `at.rufus.analysis.ui/.../dmg/*`, `biostat/.../client.dmg/*` (the graph + its viewer).
- **Specs already promise** (see `requirements.md` for the inherited/new split):
  content-hashed immutable files with pluggable backends (ics891/ics2018), UUID
  resource+version ids and id-based links (ics1602/ics416), the DMG and lineage
  (ics1107/ics1195/ics78), step/run model with a reproducible flag (ics78/ics312/
  ics439/ics510/ics939), subgraph export/import (ics461/ics2048), and a 21 CFR Part 11
  audit trail (ics454/ics2006).
- **Not in the workbench's specs** (real white-space): a first-class FOTON object, an
  `(inputs+protocol)→outputs` cache key, an opaque protocol + external executor split,
  cross-**org** federation, electronic signatures, and **anything about tool
  qualification (IQ/OQ/PQ/TQ)**.

## The world - closest analogs (ranked)

| System | What it is | Maps to plankton |
|---|---|---|
| **Bazel Remote Execution API** | build cache + exec protocol | **Architecturally exact.** A content-addressed file store (CAS) **+** a content-addressed transformation store (Action Cache: `(inputs+cmd) digest → outputs`). plankton File store = CAS; Foton = Action; "shared explorable execution cache" = the cache, made cross-org + browsable. REAPI is a battle-tested gRPC contract to mirror. |
| **Nix / Guix derivations** | reproducible packaging | The `.drv` = a content-addressed, *opaque-to-the-store* description of a transformation; store+derivation graph **is** a DMG. CA-derivations = hash/id duality; binary-cache+signatures = federation; Guix `time-machine` = long-horizon reproducibility (GxP retention). |
| **Pachyderm / W&B Artifacts** | data/ML versioning | Automatic global provenance graph (output↔input↔code-version), content-deduped. "The graph IS the product" - closest to plankton's registry-as-product. |
| **DataLad (`datalad run` + git-annex)** | decentralized data | Closest *open, federated* analog: content-addressed file keys (multi-location availability) + recorded, re-runnable command provenance. |
| **Workflow-Run RO-Crate + W3C PROV** | provenance standards | Closest *serialization* of "a foton + its files + its protocol" as a portable, cross-org, standards-based object. PROV (Entity≈file, Activity≈foton, Agent≈org) = natural interchange vocabulary. |
| **BioSimulators / BioSimulations + SBML Test Suite** | systems-biology cross-tool runs + conformance | Closest *domain/goal* cousin: a registry of containerized simulators + a reference-and-**tolerance** conformance suite (SBML Test Suite, since 2008) running a model corpus across tools - but via *standards* (SBML/SED-ML/COMBINE) + a *central* registry (standardize-and-centralize), not content-addressed federation. |
| **OpenML** | shared ML executions | datasets/tasks/flows/runs for reproducible cross-tool comparison - but a central, byte-storing platform with *metric* comparison, no content-addressed federation. |

## Layers to adopt rather than build

- **OCFL (Oxford Common File Layout)** - durable, application-independent,
  content-addressed, versioned on-disk layout. Directly serves N1 (substrate
  independent of cockpits) + GxP retention + tamper-evidence (digest manifests).
- **Sigstore (Fulcio/Rekor) + C2PA** - keyless identity-bound signatures + append-only
  transparency log + tamper-evident content manifests = the Part-11 / e-signature layer
  (N3, F7.4).
- **Content-defined chunking (HF Xet, restic/borg)** - sub-file dedup for large
  scientific files (F1.5). HF Xet is the current cross-org dedup state of the art.
- **Prolly trees (Dolt)** - content-addressing + diff for structured/tabular data
  (NONMEM datasets) (F1.5).
- **OpenLineage / Marquez** - proven Run/Job/Dataset event schema + a reference
  "graph store + API + UI-on-top" layering (a cockpit reference).
- **in-toto + SLSA + DSSE** - signed attestations about *who performed/authorized each
  step* in a supply chain; the model for plankton's **authored** foton attestations and, in
  the nekton layer, **confirmed** ray claims (F12). See `attestation.md`.
- **Nanopublications + Trusty URIs (Kuhn & Dumontier; Groth & Mons)** - the model for
  **nekton**: a small, signed, self-contained assertion, content-addressed by a
  cryptographic Trusty URI, publishable and federated across independent servers,
  ontology-agnostic. nekton is best read as **a nanopublication profile** grounded in
  plankton hashes - adopted prior art, not invention. See `../nekton/`.
- **Nix substituters · git remotes / DataLad siblings / git-annex · IPFS · Software
  Heritage** - resolve/fetch content by hash across many self-hosted instances; the model
  for **federation + mirroring** (F13). See `federation.md`.

## The genuine delta - composition, not invention

Every *primitive* below is mature and adopted; none is claimed as new. The delta is the
**inert two-layer composition** and one novel affordance, not a new primitive:

- **The composition.** plankton = in-toto/DSSE/Sigstore + SHA-256 content-addressing +
  Bazel's CAS/Action addressing + Nix's opaque-derivation-as-edge + RO-Crate/PROV
  interchange + OCFL durability - assembled into a **non-executing** results substrate
  (the counterpart to an execution API). nekton = the nanopublication/Trusty-URI model
  (Kuhn & Dumontier; Groth & Mons) as a signed, ontology-agnostic **claims** layer over
  those hashes. Two inert layers, one dividing invariant (verifiable→plankton,
  vouched→nekton).
- **The bridge (the novel affordance).** Grounding the existing **nanopublication
  statement-corpus in reproducible execution**: nekton claims point, by hash, at plankton
  fotons that anyone can re-run. Neither ecosystem spans both - the nanopublication world
  asserts without a reproducible-execution substrate underneath; the in-toto/Bazel/Nix
  world reproduces without a federated, ontology-agnostic claims corpus on top. Bridging
  them is the affordance no single existing system offers.
- **The seedchain.** The structural scope/seed/chain grammar (nekton §5.5) that lets
  independent registries overlay partial lineage by hash - the one axis (axis 4 below)
  the surveyed field leaves unmet.

We do **not** claim the world has never been "structured like this" at the primitive level
- it has; we claim the *composition* and the *bridge* are unoccupied. A focused 2026
build-vs-adopt sweep across ~30 systems checked six axes (see
`novelty-and-build-vs-assemble.md`): closest near-miss in-toto/SLSA, which plankton already
builds on. The four ingredients whose *bundling* remains unoccupied:
1. content-addressed **files AND transformations** as co-equal graph nodes;
2. **execution-agnostic / opaque typed protocols** (everyone who has the foton-edge
   also *runs* it - plankton's "store the edge, executors run it by kind" is
   unoccupied);
3. **cross-org federation by hash *with* verifiable lineage** (Bazel shares results but
   has no provenance graph; lineage tools have graphs but no cross-org dedup; HF Xet has
   cross-org dedup but no lineage);
4. **GxP/Part-11 signatures + audit + tool qualification** - carried as **nekton** claims
   over the substrate, not baked into the plankton kernel.

## Notably new (2024-2026)

- **HF Xet** default since May 2025 - production chunk-level cross-org dedup (replaced
  Git-LFS).
- **C2PA Content Credentials v2.2** (May 2025) + conformance program - signed,
  tamper-evident provenance manifests, now with AI/ML-workflow assertions.
- **EU Annex 11 revision + new Annex 22 (AI)** - draft 2025, final ~2026: raises the bar
  on audit trails, data integrity, computational provenance. Anticipate in N3.
- **Workflow-Run RO-Crate** maturing across 6+ workflow engines - emerging interop
  standard for shareable run-provenance.
- **Pharmpy** (active) - open, tool-agnostic pharmacometrics library; the natural
  NONMEM executor/parser for the DDMORE corpus (no PharmML/SO support).

## Axes 3/4/5 - focused adjudication (2026-06-18, verified)

A targeted research pass (24 primary sources, 25/25 claims verified, 0 refuted) adjudicated the three
axes left soft in the earlier sweep:

- **Axis 3 - cross-org discovery by content hash: ADOPTABLE (not novel).** DataLad/git-annex
  (content-addressed keys + multi-location availability) and Dolt (Merkle-DAG push/pull) provide it;
  Bazel CAS provides it within a build, not cross-org. A solved substrate concern.
- **Axis 5 - signed reproduction qualification with author≠confirmer: ADOPTABLE (strong model
  exists).** The **reproducible-builds** ecosystem is the direct analog: **rebuilderd** (independent
  rebuilders re-execute and attest), **repro-threshold** (a *threshold* of independent confirmers -
  author≠confirmer with a trust quorum), **pacman-bintrans** (transparency-logged signed rebuild
  attestations), over **Sigstore/Rekor** + **in-toto/SLSA/DSSE**. plankton's authored/confirmed ray
  attestations should **reference** this model; the threshold-of-confirmers maps directly onto
  plankton's tolerance/multi-confirmer trust filter.
- **Axis 4 - partial-lineage federation by hash *overlay* across independent registries: UNMET.** No
  surveyed system provides it: OCFL is single-repository (spec silent on cross-repo overlay),
  TerminusDB is git-like branch/merge collaboration (not hash-overlay federation), Dolt federates a
  *database*, not a lineage graph. This axis remains genuine white-space - **with** the integrated
  combination of 3+4+5 in one substrate.

**Net:** the differentiated claim tightens to **axis 4 + the integrated bundle**; axes 3 and 5 are
*assembled* (DataLad/Dolt; rebuilderd/repro-threshold/Sigstore), not built. Caveat: negative-from-
absence (absence of evidence within the surveyed sources).

## Key sources

- Bazel remote-apis: https://github.com/bazelbuild/remote-apis
- Nix CA-derivations: https://nixos.wiki/wiki/Ca-derivations · https://reproducible.nixos.org/
- DVC→lakeFS (Nov 2025): https://dvc.org/blog/dvc-joins-lakefs-your-questions-answered/
- Dolt prolly trees: https://www.dolthub.com/blog/2025-05-16-millions-of-versions/
- HF Xet dedup: https://huggingface.co/docs/hub/xet/deduplication
- OpenLineage / PROV: https://openlineage.io/ · https://github.com/OpenLineage/OpenLineage
- Workflow-Run RO-Crate: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11386446/
- OCFL: https://ocfl.io/
- Nanopublications (Groth & Mons): https://nanopub.net/ · https://doi.org/10.3233/ISU-2010-0613
- Trusty URIs (Kuhn & Dumontier): https://doi.org/10.1007/978-3-319-07443-6_27
- Sigstore/Rekor: https://www.sigstore.dev/ · C2PA: https://spec.c2pa.org/
- Reproducible-builds confirmer model (axis 5): rebuilderd https://github.com/kpcyrd/rebuilderd ·
  repro-threshold https://github.com/kpcyrd/repro-threshold · pacman-bintrans
  https://github.com/kpcyrd/pacman-bintrans
- 21 CFR Part 11 / Annex 11+22: https://intuitionlabs.ai/articles/audit-trails-21-cfr-part-11-annex-11-compliance
