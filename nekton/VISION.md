# Vision: nekton

> plankton drifts with the current. nekton swims.

## The other half of the record

plankton made transformations travel: data in, results out, reproducible by anyone, anywhere,
by hash. But science - especially regulated science - does not run on reproducible fact alone.
It runs on **commitments**:

- a reviewer who **signs off**,
- a tool validation that **actually happened**,
- a risk that someone **accepted**,
- a decision that a group **voted** on,
- authority one person **delegated** to another.

None of these recompute. They are true because an **accountable identity signed them** - and
false-to-trust if that identity isn't one you accept. Forcing them into plankton bloated the
substrate and blurred its one clean promise: *reproducible fact*. nekton is the other half.

## What nekton is

A **registry of signed semantic commitments**: claims - `subject → predicate → object`, signed
by an identity, scoped by context - about content-addressed things. The actively-propelled
layer of the food chain: deliberate acts by actors, not drift.

- A **claim** is *who, accountably, committed to what about which thing*. An edge, signed.
- A **predicate** is a reference into *some* vocabulary - nekton carries any, mandates none.
- The **registry** is the federated graph of claims, peers overlaying by hash.

Because subjects are hashes, a nekton claim made in one organisation **about** a plankton foton
in another splices automatically and verifiably. Because predicates are opaque, nekton never
grows an ontology engine. Because signatures are constitutive, the record is trust you can trace
to a person.

## What nekton is not

- Not plankton. plankton records what reproduces; nekton records what is vouched for. nekton
  points *at* plankton, never the reverse.
- Not an ontology. It references terms and federates equivalence claims; it defines nothing and
  reasons over nothing.
- Not a governance engine. Votes and delegations are *claims*; tallying them is a deterministic
  plankton foton; the workflow is a cockpit.
- Not a UX.

## Why minimal, and why federated

If nekton prescribed an ontology, it would inherit that ontology's ceiling and its politics. So
it prescribes none: meaning and equivalence are **signed claims like any other**, resolved
downstream over the registries each consumer can see, under each consumer's own trust policy.
The kernel stays a thin grammar of signed triples - small enough never to break, neutral enough
for any discipline to adopt. The same freedom plankton gives transformations, nekton gives
commitments.

## Direction, not destination

This starts as a scaffold. The path:

1. Pin the claim model (Ref, TermRef, the signed Claim, the registry graph).
2. A neutral reference implementation sharing plankton's stack and primitives (content-address,
   DSSE/Sigstore, federation) - no new trust layer.
3. A minimal core vocabulary (`authored`, `confirmed`, `env-qualified`, `identity-equivalent`)
   as *referenced terms*, not mandated schema - extensible to `reviewed`, `risk-accepted`,
   `vote`, `delegate`, `sameAs`.
4. Downstream resolution patterns (mapping claims + consumer-side trust policy).
5. Cockpits adopt it - a workbench first, alongside plankton.
