# Glossary

Standalone vocabulary for nekton. Terms shared with plankton keep the same meaning; nekton's
definitions are deliberately layered *on top of* plankton, never merged into it.

**nekton** - the registry of signed semantic commitments: DSSE-signed claims about
content-addressed things, federated by hash. The actively-swimming layer (vs plankton's drift).

**Claim** - the one kernel type: a signed semantic edge
`{subject, predicate, object?, context?, by, when, why?, evidence?}`. Attestable, not
reproducible. The shareable, verifiable unit. Verified by **signature**, not recomputation.

**Reproducible vs attestable** - the dividing line. A *reproducible* statement (plankton) is
checkable by re-execution / hash. An *attestable* statement (nekton) is checkable only by
*whose* signature carries it. Machine-verifiable → plankton; human-vouched → nekton.

**Ref** - a reference to a thing a claim is about: a content **hash** and/or a **URI**. May
point at a plankton foton/ray/file, another claim, an identity, or any resource.

**TermRef** - a reference to a predicate/context term in *some* vocabulary, by hash and/or URI.
nekton records it and **does not interpret it**.

**Predicate** - the relation in a claim (a `TermRef`). nekton mandates none; all uses
(`reviewed`, `confirmed`, `risk-accepted`, `vote`, `delegate`, `sameAs`, …) are just terms.

**Context** - an optional `TermRef` scoping a claim to a topic/area (e.g. the subject area of
a delegation). Also opaque to the kernel.

**Identity (`by`)** - the accountable signer: an org-PKI key (21 CFR Part 11 e-signature),
a Sigstore-Fulcio (OIDC) identity, or a DID. Whose identity *counts* is policy, not kernel.

**Vocabulary / ontology** - a set of term definitions. nekton **carries** them (by reference)
but **prescribes none**. May be published as a content-addressed file (pinned, verifiable) or
a bare IRI.

**Mapping claim** - a claim whose predicate relates two terms (`sameAs`, `broaderThan`,
`mapsTo`). The federated, signed substitute for a canonical ontology mapping table.

**Downstream / federated resolution** - meaning and equivalence are computed by **consumers**
over the union of accessible vocabularies and mapping claims, under their own trust policy -
not by the kernel. Keeps nekton minimal. (AAA: Anyone can say Anything about Any topic, signed.)

**Claim about a claim** - a claim whose `subject` is another claim's id: endorsement, dispute,
or supersession. The append-only alternative to deletion/retraction.

**Supersede** - the explicit append-only "retraction": a new claim that supersedes an earlier
one. Nothing is ever deleted (audit trail).

**Registry** - a self-hosted scope of signed claims; peers overlay by hash; there is no central
one. Same federation model as plankton.

**Splicing** - a claim made about a thing hosted in another registry connects automatically and
verifiably once both are visible, by hash equality. As in plankton lineage.

**authored / confirmed** - the two core assurance predicates migrated from plankton: *who
brought a ray in* vs *who verified it* (GxP four-eyes). Author ≠ confirmer.

**delegate / vote** - governance predicates. A delegation is one signed claim transferring
authority within a `context`; liquid democracy is an *application* of nekton, not a subsystem.

**Tally-as-foton** - counting `vote`/`delegate` claims is deterministic, so it is modelled as a
**plankton foton** whose inputs are nekton claims. nekton signs the inputs; plankton reproduces
the result. Where the brainstorm's "plankton as vote-aggregator" formally lands.

**Cockpit / Whale / Galaxy / Ray** - shared with plankton (see plankton glossary). Cockpits
read/write nekton too; whales (regulators, AI) consume signed commitments as well as
reproducible fotons.
