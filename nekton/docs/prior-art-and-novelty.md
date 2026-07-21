# Prior art & novelty map - plankton / nekton

An honest positioning of the substrate against existing work, so the genuinely novel parts stand
out and the composed parts are cited rather than re-claimed. Sourced, not asserted.

## TL;DR

Your two halves each have a mature lineage that the other half mostly lacks:

- **nekton** (signed, attributed, content-addressed statements about data, federated, ontology-
  carried-not-imposed, template-authored) is **very close to nanopublications + Trusty URIs**
  (2010–2021). This is the closest prior art and must be cited.
- **plankton** (reproducible result as a content-addressed transformation, inputs→protocol→outputs,
  signed, verified by re-execution) is **in-toto / SLSA provenance** at the wire level - which you
  already adopted - and **Unison / Nix** for content-addressed reproducible computation.
- The **epistemology** ("worlds emerge from attributed statements," non-monotonic, AAA) is a known
  Semantic-Web critique and the explicit basis of nanopublications and micropublications.

**Decision taken (2026):** nekton is adopted as a **nanopublication profile** (see
`nekton-as-nanopub-profile.md`) - statements render as nanopublications; the seedchain is a
`prev`/genesis link inside them. This is not only a reuse of *format* - it **opens a new ingestion
surface**: the cockpits can now read and contribute to the existing, live nanopublication network as
a first-class datasource (see §1.5), and it unlocks a capability neither prior ecosystem has
(§novelty: "the bridge").

**What is genuinely yours** is the *composition and the stance*: an inert two-layer base that unifies
*both* halves under one addressing/signing/federation discipline, insists the base **does nothing**,
and is offered as the substrate of **all** data processing - not just scientific assertions (nanopub)
and not just build provenance (in-toto). Plus the seed/scope chain as the single admitted kernel
grammar. Frame it as composition + stance, and it's unassailable; frame it as "no one structured the
world like this," and someone cites nanopublications in the first minute.

---

## 1. Nanopublications + Trusty URIs - the closest prior art (≈ nekton)

Groth, Gibson & Velterop (2010); Mons & Velterop (2009); Kuhn & Dumontier (2014/2015); Kuhn et al.
(2021).

- A nanopublication is a small, independent package built around an assertion, plus the provenance of that assertion, plus publication info (by whom, when, how created). That is nekton's `subject / predicate / by / when / evidence` almost exactly.
- Technically it is an RDF graph built around a subject–predicate–object assertion, extracted from a publication, enriched with provenance and publication info - the same subject-predicate-object shape you use, over opaque IRIs.
- **Content-addressing you thought was novel is Trusty URIs:** a technique to include cryptographic hash values in URIs, making resources verifiable, immutable and permanent, and making entire reference trees verifiable. Crucially, artifacts can be identified not only at the byte level but at more abstract levels such as RDF graphs, so resources keep their hash values even when presented in a different format - that is your L1 "canonical, format-independent" hashing, published in 2014.
- **Verify-by-hash federation is theirs too:** a citing nanopublication can be retrieved from anywhere, untrusted, and accepted once its content matches the hash - nekton's "splice by hash, overlay across registries."
- **Decentralized network, not a central store:** nanopublications carry Trusty-URI identifiers and are distributed and partly replicated across a server network.
- **Recursive indexes = your "aggregation is itself a record":** nanopublication indexes define sets of nanopublications and are themselves nanopublications identified by trusty URIs.
- **Template-authored UIs already exist:** nanopublications can represent reviews and method descriptions as well as findings, made immutable via Trusty URIs, with a decentralized network and template-based user interfaces such as Nanobench. That is your template idea, shipped.
- **The vocabulary-harvesting stance is theirs:** nanopublications build on the widely adopted PROV ontology to publish provenance in a granular, principled way - reuse PROV, don't reinvent.

**Takeaway:** nekton ≈ nanopublications + Trusty URIs + Nanobench. The overlap is large and honest.
Where nekton *differs* (below) is real but incremental against this line, and you should cite Kuhn &
Dumontier explicitly.

## 1.5 The reuse dividend - a new ingestion surface for the cockpits

Adopting the nanopublication profile is not only *emitting* a compatible format; it makes the
cockpits **consumers of an existing, running, federated corpus**. This is the concrete payoff of
reuse-don't-reinvent, and it belongs in the value story, not just the prior-art story.

What the cockpits can now ingest, today, with no new infrastructure:

- **A live, decentralized network** with a second-generation architecture: a **Nanopub Registry**
  (publish/retrieve), **Nanopub Query** (decentralized **SPARQL** endpoints over subsets), and
  **Nanodash** (a client that also serves as an **API/intermediary layer for other services** - i.e.
  a ready-made ingestion adapter for a cockpit).
- **A corpus already at scale.** One published analysis counted over **10.8 million nanopublications**
  (~379 million triples), and the network has grown since; existing datasets include biomedical
  resources (e.g. DisGeNET, WikiPathways, neXtProt) and domain corpora published as nanopublications.
- **Standard access**: content negotiation (TriG, N-Quads) and SPARQL - so a cockpit's ingest is a
  query, not a bespoke integration.
- **Bidirectional**: the same profile lets the cockpits **contribute back** - a acme QM review or
  a public result, once emitted as a nanopublication, is citable and queryable by the whole network.

Framing for the value story: *by expressing statements as nanopublications, the cockpit's world is no
longer just our registries - it is our registries **overlaid on** the existing nanopublication graph,
by hash.* That is the federation dividend the whole design was aiming at, arriving for free because we
reused the format instead of inventing one.

Caveat: treat this as an **edge adapter** (ingest/emit nanopublications) feeding the inert core, not
as RDF pushed into the kernel - same discipline as keeping PROV a referenced vocabulary.

## 2. in-toto / SLSA / Sigstore / DSSE - this *is* plankton's wire form (adopted, not invented)

- in-toto's atom is a lightweight "Statement" about the execution of a supply chain, carrying a "Predicate" of a context-specific type, applied to one or more "Subjects". plankton fotons and nekton claims are literally this Statement/Predicate/Subject shape - you adopted it deliberately.
- SLSA provenance captures builder identity, build instructions, parameters, environment, and dependency digests using in-toto attestations and DSSE envelopes - i.e. your foton's inputs → protocol(+environment) → outputs, signed. This is plankton's data model, already standardized.
- The link model is inputs→outputs per step: link metadata records the materials (inputs) and products (outputs) of each step, so you can verify step A produced X, consumed by step B to produce Y, each by an authorized actor. That is plankton lineage + the authority check your election aggregator does.
- **Your aggregator "gate" has a name here - the Layout:** a Layout is a document signed by the project owner defining the expected steps, who is authorized to perform each, and inspection rules applied at verification. Your seed's `responsible` set + the reproducible validity gate is an in-toto Layout specialized to federated scopes.
- Sigstore/Rekor: ephemeral OIDC-tied signing verified through a transparency log, reducing key-management burden - your identity option.

**Takeaway:** don't claim plankton's format as novel; claim the *reuse* as a feature ("trust
transfer" - same argument SLSA makes). One honest nuance worth owning: SLSA deliberately backed away
from mandating reproducible builds because reproducible and hermetic builds were considered hard in practice and were removed from SLSA 1.0. Your L0/L1/L2 reproduction-identity is a more careful answer to exactly the problem SLSA punted on - that *is* a defensible contribution.

## 3. Content-addressed reproducible computation - Unison, Nix, Merkle (≈ plankton's compute half)

- Unison: every definition is identified by a hash of its syntax tree - code is content-addressed - and the codebase is an append-only database like a Git repository. Your "reproducible code by hash," at the language level.
- The hash is structural, name/format-independent: hashes depend only on the structure of the code, not the names used, so two identically-structured functions share a hash - the compute analogue of your L1 canonicalization.
- Distribution is by hash with on-the-fly dependency sync: because definitions are content-addressed, computations can be moved between machines, with missing dependencies deployed on demand and cached - your "transport a foton by hash, fetch inputs from anywhere."
- Related, uncited but standard: **Nix/Guix** (reproducible, hash-pinned builds), **IPFS/IPLD**
  (content-addressed Merkle DAGs), **Git** (hash-linked append-only history), **OCFL** (content-
  addressed preservation). Your file/foton layer sits squarely in this family.

**Takeaway:** "reproducible result addressed by hash" is a well-populated idea. plankton's contribution
isn't the addressing; it's making the reproducible transformation an *ontology-agnostic record in a
federated attestation substrate*, decoupled from any language/build tool.

## 4. Also in the neighbourhood

- **W3C PROV, RO-Crate, Research Objects, WorkflowHub** - structure computational science as
  provenance; Research Objects are the coarse-grained cousin of your ray. You reference PROV directly.
- **Micropublications** (Clark, Ciccarese, Kinney, 2014) - enrich the nanopublication idea to cover claims made in natural language, linking claims to evidence and to other claims. This is your "attributed statement standing on evidence, disputable by other statements" - the discourse model.
- **FAIR Digital Objects (FDOF)** - minimal, free-standing, citable entities with persistent identifiers resolving to machine-actionable metadata; parallels your goals, developed alongside nanopublications.
- **Semantic-Web epistemology** - "AAA" (Anyone can say Anything about Any topic), named graphs, and
  the non-monotonic critique of one-global-truth are the intellectual soil your "worlds from
  attributed statements" grows in. State it as *taking that critique seriously as architecture*, not
  as a new discovery.

---

## Where plankton / nekton is genuinely novel

Defensible as new - the composition and the stance, not the parts:

1. **The unification.** Nanopublications give you attributed statements but have **no reproducible-
   execution half** (they cite methods; they don't carry a re-runnable transformation you verify by
   re-execution). in-toto/SLSA give you the reproducible-execution half but have **no general
   semantic-discourse half** (no ontology-agnostic, federated statements-about-anything). **plankton +
   nekton put both halves on one addressing/signing/federation substrate, cleanly separated.** That
   join - "reproducible results *and* attributable statements about them, as the two primitives" - is
   the thing you won't find pre-built.

2. **The claim of universality + inertness.** Nanopublications target *scientific assertions*; in-toto
   targets *software supply chains*. Your stance - the base is **inert** ("does nothing"), and is the
   floor under *all* data processing - is a genuinely different framing, and the "cheap because it
   refuses to do anything / refuses meaning-in-kernel / refuses money's double-spend" argument is
   yours to make.

3. **Reproduction-identity L0/L1/L2 as first-class.** A careful answer to the exact problem SLSA
   dropped. The spectrum (byte / canonical / semantic-within-tolerance) as an explicit, per-protocol,
   attestable notion is not something the prior art nails.

4. **The seed/scope chain as the *single admitted kernel grammar*.** Nanopublication indexes are
   nanopublications, and hash-linked logs exist (Git, Certificate Transparency, Rekor) - but framing a
   **seed-anchored per-registry hash-chain, with parent-registration as the unit of trust-transfer-
   beyond-a-signature, admitted as the one structural grammar while all meaning stays opaque** - that
   specific, disciplined move is novel in emphasis. (Cite CT / hash-chains so you're not re-claiming
   the mechanism, only the framing.)

5. **"plankton is never an executor" separation.** The strict inertness of the record layer, with all
   running pushed to external executors and cockpits - a cleaner architectural line than in-toto (whose
   build platform is entangled with attestation) or Unison (where the DB *is* the runtime).

6. **The bridge - grounding the existing statement corpus in reproducible execution.** This is the
   capability the composition unlocks that *neither* prior ecosystem has, and it becomes concrete now
   that the cockpits ingest nanopublications (§1.5). The nanopublication world has attributed
   statements but no re-runnable result layer; the in-toto/SLSA world has reproducible provenance but
   no open semantic-statement corpus. Once nekton statements are nanopublications and plankton fotons
   are in-toto attestations **on the same addressing/federation substrate**, an existing nanopublication
   claim can be *linked to* - or newly *grounded in* - a reproducible plankton foton by hash, and a
   reproducible result can carry attributed nanopublication claims about it. You can take a statement
   from the 10M-nanopublication graph and attach a re-runnable computation to it; nobody else spans
   both. That cross-linking, not any single primitive, is the sharpest novel affordance.

## How to position it (practical)

- **Lead with composition, not invention.** "plankton/nekton composes in-toto attestations, content-
  addressed provenance, and the nanopublication/Trusty-URI model into an inert two-layer substrate for
  all data processing." You look like someone who did the homework - and you did.
- **Cite the three anchors up front:** Kuhn & Dumontier (Trusty URIs), Groth/Mons (nanopublications),
  in-toto/SLSA. Their existence *strengthens* you: mature, adopted primitives, recombined.
- **Claim the four novel points** (unification, inertness-as-universal-floor, L0/L1/L2, the seed
  grammar) explicitly and narrowly.
- **Drop "no one has structured the world like this."** It's false at the primitive level and,
  ironically, contradicts your own epistemology. The stronger move - by your own lights - is: *here is
  my synthesis, here is what it rests on, judge it.* That framing is unattackable; the absolute-novelty
  framing has a citation waiting to puncture it in every room.

## First reading list (in priority order)

1. Kuhn & Dumontier, *Trusty URIs* (2014) and *Making Digital Artifacts Verifiable and Reliable* (2015).
2. Groth, Gibson & Velterop, *The Anatomy of a Nanopublication* (2010); Kuhn et al., *Nanobench* (2021).
3. in-toto Attestation Framework + SLSA provenance spec (you know these).
4. Clark, Ciccarese & Kinney, *Micropublications* (2014).
5. Unison "the big technical idea" (content-addressed code) for the compute-half framing.
