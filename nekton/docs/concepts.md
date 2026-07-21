# Concepts & data model

The nekton kernel is **one** type - the signed `Claim` - plus the federated registry that
holds them and the opaque `Ref`/`TermRef` it points with. Everything else (ontologies,
reasoners, tally engines, UI) is external.

> **One-line framing:** nekton is the **commitment counterpart** to plankton's reproducible
> record. plankton answers "did this `(inputs + protocol)` reproduce?" - a machine decides.
> nekton answers "who, accountably, committed to *what* about this thing?" - a signature
> decides. Same primitives, opposite epistemics.

## Ref - how nekton points at things

```
Ref := {
  hash?: ContentHash,   # sha256:…  - exact bytes / a plankton foton / a ray / another claim
  uri?:  string         # an identity, a term, an external resource
}                       # at least one of hash | uri; both = pinned + named
```

A `Ref` is the same idea as plankton's `FileRef`, generalised: a claim can be **about**
anything addressable - a foton hash, a ray, a file, *another claim* (claims about claims:
endorsement, dispute, supersession), or a plain URI. Recognisable across registries by hash.

## TermRef - the relation, without the meaning

```
TermRef := {
  hash?: ContentHash,   # content address of a term/definition, if you have one
  uri?:  string         # e.g. a vocabulary IRI: "https://kton.dev/v/confirmed",
                        #      "http://www.w3.org/2002/07/owl#sameAs", a project term…
}
```

- `predicate` and `context` are `TermRef`s. **nekton does not interpret them.** It records
  the reference and the signature; what the term *means* is an external concern.
- A vocabulary may be published *as a file* (a plankton-style content-addressed blob) and
  referenced by hash - then the definition itself is pinned and verifiable. Or it may be a
  bare IRI. nekton accepts both and validates neither.

## Claim - the only kernel type

A claim is a **signed semantic edge**.

```
Claim := {
  subject:   Ref,             # what it is about
  predicate: TermRef,         # the relation
  object?:   Ref | Literal,   # OPTIONAL target
  context?:  TermRef,         # OPTIONAL scope/topic (the "about what subject area")
  by:        Identity,        # the signer's identity (keyid / Sigstore / DID)
  when:      Timestamp,
  why?:      string,          # human rationale (free text)
  evidence?: [ Ref ]          # supporting material, by hash/URI
}
```

A claim asserts: *`by`, at `when`, accountably states that `subject` stands in relation
`predicate` to `object`, within `context`.* It is the unit that travels and the unit that is
verified - **by signature, not by recomputation**.

- **Claim id**: `sha256(canonicalJSON(Claim))` (content-addressed; identical claims coincide).
- A claim with no valid signature **is not a claim**. The signature is constitutive, not metadata.
- **Claims about claims** are first-class: `subject` may be another claim's id. This gives
  endorsement (`confirmed` a review), dispute (`disputes`), and supersession (`supersedes`,
  the append-only "retraction") for free - no special machinery.

### Predicates are applications, not kernel features

Because predicate is an opaque `TermRef`, every governance/assurance use is **just a term** -
the kernel gains nothing and needs no change:

| Use | subject | predicate | object |
|-----|---------|-----------|--------|
| Review sign-off | a ray hash | `reviewed` | - |
| Confirmation (four-eyes) | a ray hash | `confirmed` | - |
| Tool validation performed | an env hash | `validation-performed` | evidence refs |
| Env qualification | an env hash | `env-qualified` | IQ/OQ outcome |
| Identity equivalence accepted | ray-pair | `identity-equivalent` | criteria ref |
| Risk acceptance | a finding ref | `risk-accepted` | mitigation ref |
| Vote | a motion ref | `vote` | choice |
| **Delegation (liquid democracy)** | a topic `context` | `delegate` | delegate identity |
| Term equivalence | term A | `sameAs` | term B |

> The **liquid democracy / delegation** idea from the original brainstorm is therefore *not a
> separate system* - a delegation is one claim: "I delegate my approval/vote authority, in
> `context` = topic X, to identity Y." Voting and delegation are predicates over the same
> primitive.

## Registry (federated - there is no single one)

A nekton registry is a **self-hosted scope** of signed claims. Every org runs its own (public
and/or private); registries are **peers that overlay by hash**. Identical to plankton's
federation model.

```
Registry := set of Claim   (signed statements, immutable, content-addressed)
```

- **Resolution is union-by-access.** What you know about a subject `S` is the set of visible
  claims whose `subject` (or transitively, whose subject's subject) is `S`, across the
  registries you can see.
- **Splicing by hash.** A claim made here about a foton hosted elsewhere connects the moment
  both are visible - no stitching. Same rule as plankton lineage.
- **Partial knowledge is the default.** Publish only the claims you choose; a viewer without
  your private registry simply doesn't see those commitments. Granting access splices them in,
  verifiably.

## Semantic resolution - downstream and federated

This is the crux of *minimal + ontology-agnostic*:

1. nekton stores claims with **opaque** predicate/context `TermRef`s.
2. It also stores **mapping claims** - `term A sameAs term B`, `term X broaderThan term Y` -
   which are *just claims*, signed and federated like any other.
3. A **consumer** (a cockpit, a reasoner, a query) builds the meaning it needs by reading the
   union of vocabularies and mapping claims it can see, applying *its own* trust policy about
   which signers' mappings to honour.

The kernel ships **no canonical ontology, no mapping table, no reasoner**. Complexity lives in
the claim log and in consumers - keeping the core a small, durable binary. (This is the AAA /
RDF "any-to-any" principle, made signed and federated.)

## What lives where

| Concern | nekton (kernel) | external |
|---|---|---|
| Signed semantic claims (store/verify/index/federate) | ✅ | |
| Claim signatures (DSSE) verification | ✅ | |
| Federation by hash | ✅ | |
| Defining ontologies / term meanings | | vocabularies (referenced) |
| Equivalence reasoning / inference | | reasoners (consumers) |
| Vote/delegation tallying | | a plankton **foton** (deterministic) + a cockpit |
| Trust policy (whose signature counts) | | cockpit / galaxy |
| UI | | cockpits |

> **The nice loop.** Tallying a set of `vote`/`delegate` claims is a *deterministic*
> transformation: signed claims in → a result out. So the tally is a **plankton foton** whose
> inputs are nekton claims. nekton supplies the signed inputs; plankton reproduces the count.
> That is exactly where the brainstorm's "plankton as deterministic vote-aggregator" belongs.
