# nekton

A standalone registry of **signed semantic commitments** - *claims* that an accountable
identity makes **about** content-addressed things (a plankton foton, a ray, a file, another
claim, or any URI). plankton records what is **reproducible**; nekton records what is
**attestable**.

> **Charter.** nekton was extracted from plankton because attestations made the lineage
> substrate too big. plankton holds **reproducible statements** (machine-checkable by
> re-execution / hash). nekton holds **attestable commitments** (human-vouched, checkable
> only by *whose* signature carries them). Same primitives, different layer. The dependency
> points **nekton → plankton**, never the reverse. See [`docs/charter.md`](docs/charter.md).

**plankton drifts; nekton swims.** In the food chain, plankton is carried by the current -
it is the passive record of what happened to data. nekton is *actively propelled*: the
deliberate acts of accountable actors - *I reviewed this. This tool validation happened. I
accept this risk. I delegate my vote.* Both feed the whales; one is recognised by hash, the
other by signature.

## The kernel

```
Claim    := { subject:   Ref,            # WHAT the claim is about (a hash and/or URI)
              predicate: TermRef,        # the relation - a reference into SOME vocabulary
              object?:   Ref | Literal,  # OPTIONAL target (another thing, or a value)
              context?:  TermRef,        # OPTIONAL scope/topic (also just a vocab reference)
              by:        Identity,        # WHO commits (a key / Sigstore identity / DID)
              when:      Timestamp,
              why?:      string,
              evidence?: [ Ref ] }        # OPTIONAL supporting refs (also by hash/URI)

Ref      := a content hash (sha256:…) and/or a URI. Recognisable across registries by hash.

TermRef  := a reference to a term in a vocabulary/ontology - by hash and/or URI.
            nekton stores the REFERENCE. It does NOT know what the term MEANS.

Registry := the federated graph of all Claims. A claim is an edge:
            subject --predicate--> object, signed by `by`, scoped by `context`.
```

This is a **subject–predicate–object** shape (RDF-flavoured) - but every position is a
**content-addressed reference**, and every claim is **DSSE-signed**. nekton is the signed,
federated equivalent of an RDF statement store.

## We do not define meaning - we record signed statements

The single design commitment that keeps nekton small, mirroring plankton's *opaque protocol*:

- **No prescribed ontology.** A predicate is just a `TermRef`. nekton can *carry* ontologies
  (any of them), but **prescribes none**. Bring your own - GxP review vocab, a risk taxonomy,
  a voting scheme, PROV, SKOS, a one-off project term. nekton neither parses nor validates it.
- **Meaning lives downstream.** The registry records *who asserted what triple, signed*. What
  a term *means*, and whether two terms are **the same**, is resolved by **consumers**, not by
  the kernel. The complexity shifts out of the core and into the claim log itself.
- **Equivalence is just another claim - and it federates.** "term A ≡ term B" (a `sameAs`,
  `broaderThan`, `mapsTo`) is itself a signed nekton claim. There is no canonical mapping
  table. A reader resolves semantics over the **union of registries they can see** - exactly
  how plankton resolves lineage by hash. This is the **AAA** principle (Anyone can say
  Anything about Any topic), made signed and federated.

So the kernel never grows an ontology engine. It stays a thin grammar of signed triples;
ontologies, mappings, and reasoning are **external and pluggable**, overlaid by hash.

## Federated from day one

Like plankton, there is **no central registry**. Every org self-hosts its own nekton scope
(public and/or private); registries are **peers that overlay by hash**. A claim's subject is
a hash, so a claim made in one registry **about** a foton in another splices automatically and
verifiably the moment both are visible. Vocabularies and equivalence-mappings federate the
same way - you see the terms and `sameAs` claims of the registries you can access.

## Why this exists

plankton answers *"did this computation reproduce?"* - objectively, with no human in the loop.
But regulated science also runs on commitments a machine can never reproduce: a reviewer's
sign-off, a performed tool validation, an accepted risk, a recorded vote. Those are **true
because someone accountable signed them**, not because they recompute. Forcing them into
plankton bloated the substrate; giving them their own layer keeps plankton a clean record of
*reproducible fact* and gives commitments a first-class home.

## Relationship to plankton

```
            ┌─────────── cockpits ───────────┐
            │  cockpit   CLI   web   paper    │
            └────────────────┬───────────────┘
              ┌──────────────┴──────────────┐
       ┌──────▼──────┐                ┌──────▼──────┐
       │   nekton    │ ─ subject ───▶ │   plankton  │
       │ signed      │   (by hash)    │ files +     │
       │ commitments │                │ fotons +    │
       └─────────────┘                │ registry    │
        attestable                    └─────────────┘
        "I vouch …"                    reproducible
                                       "this ran …"
```

nekton claims **point at** plankton objects (and at other claims) by hash. plankton knows
nothing of nekton. Shared primitives - content-addressing, DSSE/Sigstore signatures,
federation - keep them *one system, two layers*.

A reference cockpit, **kton** (a shell CLI), conducts both layers and reimplements neither. The
acceptance test: delete kton and every operation still runs directly via `plankton` / `nekton` /
the executors. Cockpits depend on the protocols; the protocols never depend on a cockpit -
so `kton → {nekton, plankton}` and `nekton → plankton`, never the reverse. CI enforces the one
edge that is code today: the plankton kernel never imports nekton
(`scripts/check-import-direction.sh`); the cockpit direction is a design rule (kton is a shell,
not an importable module).

## Design commitments

- **Commitment, not computation.** nekton records signed assertions; it never executes,
  reproduces, or evaluates them.
- **Ontology-agnostic.** Predicates/contexts are opaque `TermRef`s. nekton carries any
  vocabulary and **mandates none**. Meaning and equivalence resolve downstream, federated.
- **Subject by hash and/or URI.** A claim is about *exactly these bytes* (hash) and/or *this
  identity/term* (URI) - recognisable across registries.
- **Signature is the trust.** A claim with no valid signature is not a nekton claim. Whose
  signature *counts* is policy, outside the kernel.
- **Append-only.** Claims are immutable and content-addressed; "retraction" is an explicit
  superseding claim, never a deletion (audit trail).
- **Assemble, don't reinvent.** Reuse in-toto/DSSE (envelope), Sigstore (identity), W3C
  PROV/SKOS/RDF (vocabulary *interchange*, not a mandated schema), multihash - same trust
  transfer as plankton. nekton writes only the thin claim kernel.

## Status

The kernel is real. A Go reference implementation ([`reference/`](reference/)) builds and passes
tests: the signed Claim wire form + claim-id, an append-log registry with the four hash indexes
(subject / predicate / signer / object), scope/seed/chain enforcement (SPEC §7.4 tamper-evidence),
and federation (serve / mirror). It reuses plankton's shared `core` (canonical JSON, hashing,
DSSE) - the one allowed `nekton → plankton` dependency. Zero-dependency companions
(`nekton-confirm`, `nekton-annotate`, the liquid-democracy `nekton-vote` executor) live in
[`cli/`](cli/) and [`executors/`](executors/). The v0 spec is [`spec/SPEC.md`](spec/SPEC.md).

See [`docs/charter.md`](docs/charter.md), [`docs/concepts.md`](docs/concepts.md),
and [`docs/glossary.md`](docs/glossary.md).
