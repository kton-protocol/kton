# Are we reinventing the wheel? Novelty, build-vs-assemble, and trust transfer

The honest due-diligence question: *does plankton rebuild something that already exists?*

**Short answer:** No single system is plankton - but nearly every *primitive* is mature and
standardized. So the rule is **assemble from established standards, don't reinvent them**.
The position is **composition, not invention**: plankton composes in-toto/DSSE/Sigstore +
SHA-256 content-addressing + the nanopublication/Trusty-URI model into an inert **two-layer**
substrate (plankton = reproducible results; **nekton** = signed, ontology-agnostic claims about
them). The delta is that *composition* plus one novel affordance - **the bridge**: grounding the
existing nanopublication statement-corpus in reproducible execution (neither ecosystem spans both)
- plus the seedchain. Not a claim of new primitives; the kernel is small precisely because the
hard parts are adopted, not written.

## Closest real, working neighbors - and exactly where each stops

| System | How close | Where it stops for us |
|--------|-----------|------------------------|
| **in-toto / SLSA** | *Very close on foton + attestation.* An in-toto "link" already records `materials` (inputs) → step → `products` (outputs), signed, by whom, in a DSSE envelope, chainable. Our foton + authored/confirmed attestation is essentially **in-toto generalized**. | A **verification format**, not a federated, queryable, content-addressed **registry**: no cross-org discovery, no alternative-scenario queries, no reproduction-identity / qualification, no partial-lineage publishing. Threat model is *software* supply chain. |
| **Nix / Guix** | The closest **working** content-addressed, federated, signed transformation graph (derivations = fotons, store = CAS, binary caches = federation, signed substituters = trust). | **Executes** (not opaque protocol); for **software builds**, not arbitrary data; mostly input-addressed; no discovery, no GxP qualification, no partial-lineage federation. |
| **OCI registry + cosign + SLSA** | Deployed, signed, content-addressed artifact graph with attached attestations (referrers API). | Artifact-centric, **no lineage graph / queries**, no transformation discovery, no scientific/GxP semantics. |
| **RO-Crate + WorkflowHub** | The science-domain "publish a reproducible run with PROV" story. | Packaging + a registry, **not** a federated content-addressed cache with cross-org dedup/discovery + qualification. |
| **OpenLineage / DataHub / Atlas** | Mature lineage graphs + UIs. | **Name-based**, not content-addressed; no federation-by-hash; no signatures-as-trust; no qualification. |
| **Nanopublications + Trusty URIs** (Kuhn & Dumontier; Groth & Mons) | *Directly the model for nekton*: small, signed, self-contained assertions, content-addressed by cryptographic Trusty URI, federated across independent servers, ontology-agnostic. **Adopted, not reinvented** - nekton is a nanopublication profile. | The corpus **asserts** but has no reproducible-execution substrate underneath (no fotons, no re-runnable results to point at). plankton supplies exactly that ground - **the bridge**. |
| **Blockchain "federated provenance" research (2025)** | Same goals (federated, verifiable provenance). | Research; blockchain-anchored; not a deployable, content-addressed substrate for scientific data. |
| **DataLad / git-annex** | decentralized data + provenance | Closest *substrate* cousin: content-addressed (git-annex keys), decentralized/federated (siblings), `datalad run` re-runnable provenance, partial availability. Stops at: dataset-centric recorded *commands* (not an opaque-protocol foton graph), no cross-org discovery-by-hash, no qualification; git-rooted (imposes git as the metadata substrate). |
| **BioSimulators / BioSimulations + SBML Test Suite** | systems-biology cross-tool runs + conformance | Closest *goal* cousin: a registry of containerized simulators + a reference-and-**tolerance** conformance suite (SBML Test Suite, since 2008) running a model corpus across tools. Stops at: built on *standards* (SBML/SED-ML/COMBINE/OMEX) + a *central* registry - standardize-and-centralize, not content-addressed federation with opaque protocols. |
| **OpenML** | shared ML executions | Shared datasets/tasks/flows/runs for reproducible cross-tool comparison. Stops at: central platform, byte-storing, *metric* comparison (not reproduction-identity/tolerance), no content-addressed federation. |

## The unoccupied combination (the actual delta)

Not a claim that the world has never been "structured like this" - at the primitive level it has.
The delta is the **inert two-layer composition + the bridge**, i.e. no one *combines* **all** of:
1. content-addressed **files AND transformations** as co-equal nodes;
2. **opaque protocol + external executor** (everyone else *executes*);
3. **cross-org discovery / alternative scenarios** by input hash;
4. **partial-lineage federation** (publish from a boundary; lineage resolves over what you
   can see) - the seedchain;
5. a signed, **ontology-agnostic claims layer (nekton)** grounding the nanopublication
   statement-corpus in those re-runnable results - reproduction identity, normalization-as-foton,
   ray-level signed confirmation, GxP tool-qualification - carried as claims *about* fotons, not
   baked into the results kernel.

Aimed at **scientific data**, that *composition* - two inert layers split by the
verifiable/vouched invariant, bridged by hash - is what is unoccupied. Each ingredient is adopted.

### Build-vs-adopt verification (2026) - and the cleanest statement of the gap

A focused build-vs-adopt sweep (2026) tested this against ~30 candidate systems across data
engineering, ML-ops, scientific reproducibility, FAIR, supply-chain, and content-addressed storage,
scored on six axes: (0) substrate-not-executor, (1) content-addressed files *and* transformations,
(2) opaque protocol + external executor, (3) cross-org discovery-by-hash, (4) partial-lineage
federation, (5) signed four-eyes reproduction/tolerance qualification. **No single system covers all
six.** Each fails a *discriminating* axis structurally, not cosmetically: metadata standards
(OpenLineage) are name-keyed not content-addressed; workflow engines (Nextflow, …) execute and
comprehend the workflow (fail 0, 2); packaging profiles (CWLProv) bundle the bytes (fail 0);
content-location services (Software Heritage) are one centralized archive (fail 4); a
Hyperledger-Fabric federated-provenance design is a PID-keyed consortium ledger (fails 1, 4).

The **closest near-miss is the standard plankton already builds on** - in-toto/SLSA: the link
predicate matches the foton inputs→command→outputs shape with opaque environment/byproducts, and
SLSA `buildType` is an externally-interpreted opaque descriptor - but it has no cross-org hash
discovery (3), no partial-lineage federation (4), and no mandated author≠confirmer signing (5). So
the novelty states cleanly **by subtraction**:

> **plankton = in-toto/SLSA's attestation shape + { discovery-by-hash, partial-lineage federation }
> - a content-addressed transformation graph that owns no bytes and executes nothing; with
> **nekton** (a nanopublication/Trusty-URI profile) adding the signed four-eyes
> reproduction/tolerance qualification as ontology-agnostic claims about those results.**

The obvious rebuttal - *just compose in-toto + Rekor + IPLD/OCFL* - does not dissolve it: even
composed, you must still **build the federation (4) and qualification (5) glue**, and that glue *is*
plankton's kernel. Adopt the formats; the integrating kernel is the unoccupied remainder. (Honest
caveat: ~9 systems firmly adjudicated, ~25 more by structural reasoning; the Workflow-Run RO-Crate
profile and the Sigstore/Rekor evolution are where a near-miss could still shift - close that gap
before committing the claim to a paper.)

## Build vs. assemble - what we adopt vs. write

| Layer | **Adopt** (don't build) | License |
|-------|--------------------------|---------|
| content addressing | multihash / Multiformats; existing CAS | MIT |
| attestation envelope | **in-toto / DSSE** | **Apache-2.0** (CNCF *Graduated*, Feb 2025) |
| identity, signing, transparency | **Sigstore** (cosign / Fulcio / Rekor) | Apache-2.0 (CNCF, LF public-good) |
| build-level provenance predicate | **SLSA** | Apache-2.0 / CC-BY |
| signed claims layer (nekton) | **Nanopublications + Trusty URIs** (nekton = a profile) | open / academic (freely implementable) |
| lineage interchange / ontology | **W3C PROV / PROV-O** | W3C royalty-free (free to implement) |
| publish/package a run | **RO-Crate** (+ Workflow-Run profile) | CC-BY 4.0 (spec); Apache-2.0 (tooling) |
| federation / mirroring patterns | Nix-substituter, git-annex, IPFS *(patterns)* | - |
| bytes (external) | S3 / OCI / IPFS | Apache-2.0 / MIT |

**Everything we adopt is permissive (Apache-2.0 / MIT / CC-BY / W3C-RF)** - no copyleft
contamination, commercially embeddable, independent of whatever license plankton itself
chooses.

What is genuinely **ours to write** (small): the thin metadata kernel tying these together
for **arbitrary data transformations** - opaque protocol + executors, discovery,
partial-lineage federation (the seedchain) - plus, in the **nekton** layer, the signed
domain claims (reproduction-identity, qualification) as a nanopublication profile over the
plankton results. Two inert layers; the split is the verifiable/vouched invariant.

## Trust transfer - the strongest argument for assembling

Assembling from established standards **transfers their accumulated trust to plankton**.
This is two distinct wins:

- **Security.** "Don't roll your own crypto / format." A CNCF *Graduated* project (in-toto)
  and a Linux-Foundation public-good transparency log (Sigstore/Rekor) carry independent
  audits, broad production adoption, and active security maintenance. Reusing them imports
  that assurance; inventing our own means re-earning it from zero.
- **Regulatory / GxP.** Leaning on **pre-validated, recognized** components shrinks our own
  validation surface and speeds auditor acceptance. PROV (a W3C Recommendation) and RO-Crate
  (adopted across science) similarly transfer **scientific-community** credibility. An
  auditor who already accepts in-toto/Sigstore attestations does not need to be re-convinced
  of plankton's signature layer - only of how we *compose* it.

It also **defuses the "are we redundant?" worry**: by assembling, plankton is explicitly
*not competing* with in-toto/Nix/Sigstore - it *composes* them into the niche they don't
serve.

### Honest limits of trust transfer
- in-toto's **threat model is software supply chain**; using it for scientific data is a
  *repurposing*. The format transfers; verify the predicate model fits and that we don't
  lean on guarantees outside its designed scope.
- You inherit upstream **governance, roadmap, breaking changes** (mitigated: these are
  stable, graduated, versioned standards).
- Trust transfers **only if used idiomatically** - misusing a trusted format transfers no
  trust.

## Recommendation

Before the formal `spec/`, run a **build-vs-assemble spike**: express one Warfarin foton +
its qualification verdict as an **in-toto/DSSE statement, signed via Sigstore**, in a
trivial index. If it carries cleanly, the spec becomes *"plankton = in-toto/DSSE predicates
+ PROV/RO-Crate interchange + a federation/discovery API + qualification semantics"* - and
we adopt rather than invent the entire trust+format layer. If it doesn't fit, we'll know
exactly which gap forces a custom piece.

## Sources

- in-toto Apache-2.0 + CNCF Graduation (Feb 2025): https://www.cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries/ · https://github.com/in-toto/in-toto-golang
- in-toto / SLSA: https://slsa.dev/blog/2023/05/in-toto-and-slsa
- Nanopublications (Groth & Mons): https://nanopub.net/ · Trusty URIs (Kuhn & Dumontier): https://doi.org/10.1007/978-3-319-07443-6_27
- Sigstore: https://www.sigstore.dev/
- W3C PROV: https://www.w3.org/TR/prov-overview/
- RO-Crate: https://www.researchobject.org/ro-crate/
- Federated provenance research (arXiv 2025): https://arxiv.org/html/2505.24675
