# Requirements

Status: **draft for discussion.** This captures what plankton must do, separating
what is **[INHERITED]** from the workbench's existing specs (we are extracting, not
inventing) from what is **[NEW]** white-space the workbench does not yet promise.

Requirement references (ics*) map to the founding specification set.

## Framing: the counterpart to an execution API

plankton is **a shared, explorable execution cache** - the read/write/explore side of
a content-addressed `(inputs + protocol) → outputs` store. An **execution API** (the
*executors*, external) answers "run this." plankton answers "has this been run, by
anyone, and what came out?" This is the Bazel Remote Execution shape (CAS + Action
Cache) generalized to: cross-org sharing, an opaque/typed protocol the substrate does
not execute, an explorable lineage graph, and GxP/qualification semantics.

Three use cases, one mechanism:
- **Reuse / dedup** - a cache hit (same inputs+protocol seen before, anywhere) skips
  recomputation and recognizes identical work across organizations.
- **Tool qualification** - the cached output is a *known-correct reference*; re-running
  the protocol and comparing results *is* operational-qualification (OQ) evidence.
- **Lineage / provenance** - the cache, explored as a graph, is the DMG.

---

## Functional requirements

### F1 - Files: addressed by hash, located by uri (NO kernel filestore)
- **F1.1** Every file identified by a content hash (SHA-256). [INHERITED - ics891 /
  ics2018: hash computed on upload, exposed for integrity verification.]
- **F1.2** **plankton stores no bytes.** A `FileRef = {hash, path?, uri?, id?}` is
  sufficient: the registry is pure metadata; bytes live wherever they already are (S3, OCI, a
  lab filesystem, DDMORE's URL). Trust the hash, not the uri. [NEW - the workbench *is* a
  filestore (ics891/ics2018); plankton deliberately is not. A filestore becomes one
  optional, pluggable uri target, not the substrate.]
- **F1.2a** `FileRef.path` is the file's **relative** path in the foton work tree
  (structural - part of identity/action key); the **absolute sandbox root is incidental and
  never recorded** (PsN subfolders, `raw/...`). Inputs/outputs are path→hash trees. [NEW.]
- **F1.3** A file may have **many uri locations** (available from several places);
  *availability* of bytes is a separate property from *identity*, needed only to **re-run**
  a foton (re-execution/qualification) - see F9.4 completeness. [NEW.]
- **F1.4** Long-term **retention / pinning is optional and pluggable** (cf. Guix ↔
  Software Heritage), not a kernel concern. GxP retention = pin the hashes that matter.
  [NEW.]
- **F1.5** Versions immutable. [INHERITED - ics452.]
- **F1.6** Canonicalization for cross-org hash agreement (encoding/line-endings; tabular
  normal form) - achieved by **normalization fotons**, not a kernel filestore feature.
  A file's "canonical hash" is just the raw hash of a normalization foton's output. See
  `reproduction-identity.md`. [NEW.]
- **F1.7** Large/mutated files addressed efficiently (content-defined chunking and/or
  prolly-trees) where a backend *does* store bytes - a backend concern, not the kernel.
  [NEW.]

### F2 - Identity (hash + id duality)
- **F2.1** Persistent UUID per resource and per version. [INHERITED - ics1602:
  resourceId + resourceVersionId.]
- **F2.2** References by id, surviving moves/renames (Links). [INHERITED - ics416 Link,
  targetId/targetVersionId.]
- **F2.3** A `FileRef` = **hash and/or id**: hash-only (exact bytes), id-only (current
  target of an identity), or both (pinned + verifiable). [NEW - make the duality
  explicit and define its federation semantics.]
- **F2.4** Globally resolvable identifiers (URL form) for cross-org reference. [NEW -
  vision-level; ics1602 IDs are repo-local UUIDs today.]

### F3 - Fotons (transformations as edges)
- **F3.1** A foton stores `inputs[] (FileRef) → protocol → outputs[] (FileRef)` and is
  itself content-addressable. [NEW as a first-class object - the workbench has Step/Run
  (ics78/ics312/ics439) and a "reproducible" flag (ics939), but no FOTON object and no
  `(inputs+protocol)→outputs` cache key.]
- **F3.2** Parental relation from every output to every input. [INHERITED - ics78: all
  output files parental-related to all input files of the run.]
- **F3.3** Immutable run/foton records. [INHERITED - ics312 run records; ics2006 audit
  immutability.]
- **F3.4** Action-cache lookup: given `(inputs + protocol)` digest, return prior
  outputs if present. [NEW - the "shared execution cache" core.]

### F4 - Opaque, typed protocol + external executors
- **F4.1** Protocol stored as `{ref (content hash), kind}`; the substrate never
  executes it. [NEW - the workbench's Step binds tool+runserver+command (ics510) and
  executes; plankton deliberately externalizes execution.]
- **F4.2** An executor interface: external runners register by `kind` and fulfill
  `(inputs, protocol descriptor) → outputs`. plankton is the counterpart, not the
  runner. [NEW.]
- **F4.3** The **execution environment** is a first-class, **typed, content-addressed,
  extensible** entity carried in the protocol (and thus in `protocol.ref` and the action
  key): `Environment{kind, ref, descriptor}`, kind ∈ {oci/docker-by-digest, nix, guix, renv,
  apptainer, conda, **workbench-tool-instance**, …}. Same inputs+protocol *incl. env* → same
  outputs; a different/absent env is a different computation. [NEW; this is what the workbench's
  **tool instances** (`runserverToolId`) are - generalised and made portable.]

### F5 - Registry as explorable lineage graph
- **F5.1** Bidirectional lineage: "where did this come from" / "what depends on it",
  scoped to a tree or the whole registry. [INHERITED - ics1195 Lineage; ics1107 DMG.]
- **F5.2** Views (trees) are projections over the graph, owned by cockpits, not by the
  substrate. [INHERITED conceptually - ics441 Analysis Tree vs ics1107 DMG.]
- **F5.3** Query API for the graph (independent of any UI). [NEW - the workbench's DMG is a
  client/editor; plankton needs a headless, cockpit-agnostic query surface.]

### F6 - Import / export / federation
- **F6.1** Package a subgraph (fotons + files or just hashes + metadata) for transport.
  [INHERITED - ics461 Exporting; ics2048 workflowOperations: JSON template, tool
  mapping, variable binding, dependency preservation, cycle detection.]
- **F6.2** Cross-**organization** federation by hash (recognize/import foreign fotons
  and files). [NEW - the workbench has cross-repo *scripts* (run-crossrepo*) but no spec; no
  cross-org trust model.]
- **F6.3** Lazy materialization: move digests, fetch bytes on demand. [NEW.]

### F7 - Tool qualification (the keystone use case)

> **Layer split.** The *mechanical* comparison (F7.1–F7.4: the reference foton, the re-run, the
> L0/L1/L2 compare) is a **plankton** `kind=compare` foton. The *confirmation* - the signed
> **verdict/acceptance** (F7.5) and the **environment-qualification attestation** (F7.7) - is the
> **nekton** layer, not the plankton kernel. See [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md)
> and [attestation.md](attestation.md).

- **F7.1** A foton with known inputs and known-correct outputs serves as an **OQ test
  case**. [NEW - no IQ/OQ/PQ/TQ specs exist in the workbench today; complete white-space.]
- **F7.2** Qualification run = execute protocol via an executor, compare result to the
  reference foton's outputs; a pass is qualification evidence. [NEW.]
- **F7.3** Comparison uses an explicit **equivalence relation coarser than
  byte-equality** - byte-identity (L0) is the wrong test because correct re-runs embed
  incidental content (licensee, date, paths) and legitimately differ numerically. Three
  levels: **L0** byte-identical, **L1** canonically-identical (after normalization),
  **L2** semantically-equivalent (parsed results within tolerance). NONMEM qualifies at
  L2. Full model in `reproduction-identity.md`. [NEW.]
- **F7.4** **Equivalence criteria are first-class artifacts** - a normalization profile
  and a tolerance spec, each keyed by `protocol kind` + file role, **content-addressed,
  versioned, and signed**. Declaring exactly which differences are non-meaningful (and
  the accepted tolerance) *is* the OQ acceptance criterion - auditable and reproducible.
  [NEW.]
- **F7.5** A qualification verdict records the **level reached**, the **criteria ids**,
  and the **residual diff**; comparison is like-for-like (same tool version + estimation
  method) or downgraded to "consistency", not "reproduction". [NEW.] *(The mechanical diff is
  a plankton `kind=compare` foton; its signed **acceptance** as a verdict is a **nekton** claim -
  see [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md).)*
- **F7.6** Qualification produces a durable, signed record (validation-as-byproduct of
  normal lineage capture; cf. copy-graph-to-qualified-workflow). [NEW.]
- **F7.7** **Environment qualification (the TQ link).** An `environment-qualification`
  attestation records a tool/environment's IQ/OQ (subject = the environment's content
  address). A result is trustworthy only if its environment carries a valid such attestation
  from a trusted qualifier - "executed by a tool that passed a defined qualification." This is
  distinct from the result verdict (F7.1–F7.5): one qualifies the *tool*, the other the
  *output*. [NEW - this is the origin of the whole tool-qualification use case.] *(Realised by
  **nekton**, not the plankton kernel: this attestation is a signed claim keyed by the
  environment hash - see [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md).)*

### F8 - Seed / ingest
- **F8.1** Bulk ingest of external corpora into the registry. [NEW.]
- **F8.2** First corpus: **DDMORE Model Repository** (CC0) as a qualification reference
  set - model entries map to files + fotons.
  [NEW.]

### F9 - Publishing & adapters (the write side)
- **F9.1** A publishing API: any producer records a foton `(inputs, protocol{ref,kind},
  outputs)` **post-hoc, without plankton executing anything**. [NEW.]
- **F9.2** Two write paths, same cache: **execute-then-record** (an executor runs a
  protocol) and **observe-and-publish** (an adapter harvests a foton from a tool that
  already ran). [NEW.]
- **F9.3** Adapters extract fotons from existing flow/build tools - Make, Snakemake,
  Nextflow, CWL, Bazel, CI jobs, shell - **at whatever granularity the source exposes**
  (one target/rule/step = one foton, or a whole run = one foton). [NEW.]
- **F9.4** Every foton carries an explicit **completeness level**: fully-pinned +
  re-runnable + qualified → observed (inputs/outputs/kind known) → lineage-only (protocol
  opaque). Reuse/qualification gate on the top; discovery works all the way down. [NEW.]

### F10 - Discovery (the payoff of content-addressing)
- **F10.1** Index fotons by input set; query "what else consumed file/hash X" returns
  all alternative protocols/outputs = **alternative scenarios**, across galaxies. [NEW -
  the workbench lineage (ics1195) is within-repo, single-direction; this is cross-org fan-out.]
- **F10.2** Three queries off one index: same `(inputs+protocol)` → **reuse**; same
  inputs, different protocol → **alternative scenarios**; **equivalent outputs** across
  different protocols → **cross-tool equivalence** (independent corroboration; basis for
  qualifying one tool against another). Note: "equivalent" means **same canonical/
  semantic form (L1/L2)**, not same raw hash (L0) - tool outputs rarely share raw bytes.
  See `reproduction-identity.md`. [NEW.]
- **F10.3** Pre-compute check: before running, ask the cache whether the result exists
  (reuse) or whether the inputs already have outputs via other protocols (alternatives).
  [NEW.]

### F11 - Global addressability & publishing subgraphs (papers / WebRay)
- **F11.1** Every file and every foton is independently **globally addressable and
  citable** (URL form). [NEW - strengthens F2.4; the workbench IDs are repo-local UUIDs.]
- **F11.2** Publish a subgraph as a citable package (a **WebRay**): a paper references
  fotons+files by global address; a reader fetches any step, verifies it by hash, and
  re-runs the runnable ones. [NEW - extends F6 export to public, citable, verifiable
  publication.]

### F12 - Provenance & attestation (who brought in, who confirmed)

> **Realised by NEKTON, not the plankton kernel.** All of F12 is the **nekton** layer - signed
> claims about plankton results, keyed by subject hash, rendered as nanopublications and federated
> independently. plankton records only fotons; the "stores and verifies attestations" role below is
> nekton's. Dependency: nekton → plankton, never the reverse. Spec:
> [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md); rationale: [attestation.md](attestation.md).

- **F12.1** **Authored** attestations: who *brought a ray in* (submission provenance,
  first-party). [NEW.]
- **F12.2** **Confirmed** attestations: who *verified a ray* (third-party). Author ≠
  confirmer (GxP four-eyes); independence is recordable and enforceable by policy. [NEW -
  the workbench has review states + Part-11 e-sig as precedent; not in the registry substrate.]
- **F12.3** Attestation **subject may be a ray (subgraph) or a ray-pair**, not only a
  foton - because normalized identity lives at ray endpoints. `identity-equivalent`
  attests "ray A ≡ ray B under criteria C"; `qualified` attests "ray meets OQ criteria
  C". **You confirm rays, not every foton.** [NEW.]
- **F12.4** An attestation is a **digitally signed claim** (signer + meaning + timestamp)
  = a 21 CFR Part 11 electronic signature; carries evidence (e.g. the comparator verdict
  foton) and criteria ids. **nekton** (not the plankton kernel) **stores and verifies**
  attestations; it does not produce them. [NEW; satisfies part of N3.]
- **F12.7** **Sign claims, not bytes** - content-addressing secures bytes (integrity);
  signatures add attribution. Use a **DSSE-style envelope** signed over literal payload
  bytes (keeps signing independent of foton canonical-hashing, N6). [NEW.]
- **F12.8** **Identity binding**: org PKI / X.509 for regulated signers (accountable
  person/org), and/or Sigstore-Fulcio keyless (OIDC) / DIDs for federation; optional
  **transparency log** (Rekor-style) for tamper-evident, no-secret-retraction history.
  Key rotation/revocation via short-lived certs + log, or CRLs. [NEW.]
- **F12.9** Signatures are **host-independent** - they survive mirroring/federation and are
  re-verified by any peer (trust the signature, not the host). [NEW.]
- **F12.5** `retracted` attestation for immutability-safe correction/supersession (never
  delete). [NEW.]
- **F12.6** Trust policy (whose confirmations count) is a **cockpit/galaxy** concern; the
  kernel only stores + verifies signatures. [NEW.]

### F13 - Federation (self-hosted registries, partial lineage by default)
- **F13.1** **No central registry.** Every org **self-hosts** its own (a university, a
  pharma, a lab); typically a **public** instance (shared) and a **private** one (kept).
  Registries are peers. [NEW - the workbench has cross-repo *scripts*, not federation.]
- **F13.2** **Lineage resolves over the union of accessible registries**, joined by file
  hash: a file's producer = a visible foton whose output is that hash. [NEW.]
- **F13.3** **Partial lineage is the default**, not a feature: an input hash with no
  visible producer is a **lineage root** (a `{hash, uri}` file without lineage). Selective
  publication = publish only the fotons from a chosen boundary (e.g. aggregated data)
  onward. [NEW.]
- **F13.4** **Verifiable splicing**: on gaining access, a private foton's output hash ==
  the public foton's input hash → graphs join cryptographically, no manual stitching.
  [NEW.]
- **F13.5** **Sync = set reconciliation** of append-only, content-addressed records (same
  record → same hash → conflict-free union; Merkle-style diff). Metadata only; bytes by
  uri on demand. [NEW.]
- **F13.6** Small **federation API**: `get-foton-by-output(hash)`, `uses(hash)`,
  `get-ray`, `attestations(subject)`, `sync(since)` - all under **access control**; public
  endpoints expose only the public scope. [NEW.]
- **F13.7** **Privacy of content-addressing**: a hash is a confirmation oracle for
  guessable sensitive data. Publish only at safe boundaries; support **salted/HMAC**
  content addresses for sensitive files; keep sensitive scopes private. [NEW.]
- **F13.8** **Mirroring**: any visible registry can be **pulled, persisted, and
  re-served** - metadata only, or **also pinning the bytes** into your own backend
  (uri-rot defence + GxP retention; e.g. mirror+pin DDMORE → durable re-runnable corpus).
  Mirroring = sync (F13.5) with persistence; a mirror is itself a peer/cache. Mirroring
  ≠ confirming - attestations retain their original signer. [NEW; this is how F1.4
  optional pinning/retention is realised.]

---

## Non-functional requirements

- **N1 Application-independence.** The substrate is rebuildable without any cockpit;
  prefer an app-independent, content-addressed on-disk layout (OCFL-style). [NEW as an
  explicit constraint - today the DMG is the workbench/Java-owned.]
- **N2 Neutral & portable.** Reference implementation in a neutral language
  (Go/Rust/Python), no the workbench/R/Java dependency. [NEW.]
- **N3 GxP / 21 CFR Part 11 + EU Annex 11/22.** Immutable append-only audit trail;
  electronic signatures (signer + meaning + timestamp); long-term retention; tamper
  evidence. [PARTIAL INHERITED - ics454 audit trail (§11.10), ics2006 immutability +
  file_hash; NEW: e-signatures, transparency-log-style tamper evidence, retention of
  inputs so they never vanish.]
- **N4 Scale.** Large files (chunking), millions of files, lazy materialization. [NEW.]
- **N5 Reproducibility as documented convention.** Same inputs+protocol → same outputs
  is designed-for and attested, not enforced; non-deterministic steps handled honestly.
  [INHERITED stance - glossary; PARTIAL via ics939.]
- **N6 Canonical graph serialization.** The registry/graph encoding is itself canonical
  so two orgs describing the same lineage produce the same hash. [NEW.]
- **N7 Trust model for federation.** Decide verify-by-re-execution vs attest-by-
  signature (or both, per kind). [NEW.]
- **N8 Assemble, don't reinvent (trust transfer).** Adopt established, permissively-
  licensed standards for every hard layer - **in-toto/DSSE** (attestations), **Sigstore**
  (identity/signing/transparency), **W3C PROV / RO-Crate** (lineage interchange),
  **multihash** (addressing). This imports their security audits and regulatory/scientific
  credibility (CNCF-graduated, W3C-Rec, LF public-good) instead of re-earning trust from
  zero - a security *and* GxP-validation win. plankton writes only the thin kernel +
  domain semantics. See `novelty-and-build-vs-assemble.md`. [NEW.]

---

## The hard problems (where the real design work is)

1. Content-addressing large/mutable scientific data + a stable canonical form (F1.4/F1.5).
2. Hash↔id duality semantics under federation (F2.3).
3. Protocol opacity vs the reproducibility that cross-org trust + qualification need
   (F4/F7/N5).
4. Federation trust: verify vs attest (N7).
5. GxP immutability vs erasure/retraction/GC (N3).
6. Canonical serialization of the graph itself (N6).
7. Qualification under non-determinism: tolerance comparison, version pinning (F7.3).

---

## Inherited-vs-new at a glance

| Area | Inherited (the workbench ICS) | New white-space |
|------|--------------------------|-----------------|
| File hashing, immutability, backends | ics891, ics2018, ics452 | canonicalization, chunking |
| IDs / links | ics1602, ics416 | hash+id `FileRef`, global URLs |
| Lineage / DMG | ics1107, ics1195, ics78 | headless query API, cross-org |
| Step / Run | ics78, ics312, ics439, ics510, ics939 | **FOTON object**, action-cache key |
| Protocol / execution | ics510 (binds+executes) | **opaque protocol + external executor** |
| Export / import | ics461, ics2048, ics1169/70 | cross-**org** federation, lazy bytes |
| Audit / Part 11 | ics454, ics2006 | e-signatures, transparency log |
| **Tool qualification** | - (none) | **F7 entirely new** |
| **FOTON / determinism** | ics939 (flag only) | first-class FOTON + convention |
| Seed / DDMORE | - | F8 entirely new |
| **Publishing / adapters** | - | **F9 entirely new** (observe-and-publish) |
| **Discovery / scenarios** | ics1195 (within-repo) | **F10** cross-org fan-out |
| **Global addressing / papers** | repo-local UUIDs | **F11** citable WebRay |
| **Attestation (who/confirm)** | review states + Part-11 e-sig | **F12** ray-level authored/confirmed |
| **Federation** | cross-repo scripts | **F13** self-hosted peers, partial lineage |
