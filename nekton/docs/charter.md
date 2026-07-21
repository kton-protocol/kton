# Charter - what nekton is for

**Origin.** nekton was extracted from plankton. The attestation types
(`authored`, `confirmed`, `environment-qualification`, `identity-equivalent`) made the
lineage substrate too big - and they are not reproducible facts, they are **signed
commitments**. They belong in their own layer.

**Mission.** A minimal, federated registry of **signed semantic commitments** that plankton,
the workbench, and others use to attest reviews, performed tool validations, risk decisions, votes,
delegations, and equivalence - anything that is *true because someone accountable signed it*.

nekton is a **sister layer** to plankton, not a part of it. The dependency points
**nekton → plankton**, never the reverse.

## The dividing line (the invariant)

> Can a machine **verify** the statement (re-execution / hash) → **plankton**.
> Can it only be **vouched for** by a person → **nekton**.

| | **plankton** | **nekton** |
|---|---|---|
| Statement kind | reproducible | attestable |
| Checked by | re-execution / hash - a machine | signature + trust - a human vouches |
| Truth dimension | true / false (objective) | trusted / not (whose signature?) |
| Needs a person | no | yes |

This is a real, falsifiable test - not a feeling. It is what keeps plankton small again.

## Same system, two layers - shared primitives

nekton is separate but not foreign. Both layers share:

- **content-addressing** (multihash / `sha256:…`)
- **signature envelope** (in-toto / DSSE, Sigstore)
- **federation** (registries as peers, overlay by hash)
- **identity / key management**

nekton is "plankton grammar for commitments instead of transformations": the same signed
statements, a different predicate.

## What migrated out of plankton

| was in plankton | → nekton predicate (a `TermRef`) | the commitment |
|---|---|---|
| `authored` | `authored` | "I brought this ray in." |
| `confirmed` | `confirmed` | "I verified this ray." (four-eyes) |
| `environment-qualification` | `env-qualified` | "This environment passed IQ/OQ." |
| `identity-equivalent` | `identity-equivalent` | "Ray A ≡ Ray B under criteria C - accepted." |

After migration the **plankton kernel is attestation-free**: only `File`, `Foton`,
`Protocol{kind,ref}`, `Registry` - pure reproducible fact.

> **The reproduction-identity cut.** The *mechanical* equivalence check (L0/L1/L2 against a
> normalization profile, recomputable) stays plankton. The *signed acceptance* of that
> equivalence is the nekton `identity-equivalent` claim. The profile is plankton data; the
> signature on it ("this is the valid OQ acceptance version") is nekton.

## The three layers (how the predicates cluster)

nekton mirrors plankton's three-layer framing, but for commitments rather than transformations:

| Layer | What nekton provides | Example predicates |
|-------|----------------------|--------------------|
| **Assurance** | sign that work was reviewed / a tool was validated / an env qualified | `confirmed`, `reviewed`, `env-qualified`, `validation-performed` |
| **Governance** | record risk decisions, approvals, votes, delegations | `risk-accepted`, `approved`, `vote`, `delegate` |
| **Semantics** | assert what terms mean and how they relate - federated, no canonical map | `sameAs`, `broaderThan`, `mapsTo`, `definedBy` |

All three run on one kernel: a signed `Claim{subject, predicate, object?, context?, by, …}`,
content-addressed, DSSE-signed, federated by hash. The layers are *uses*, not separate systems.

## Minimal - and ontology-agnostic

The discipline that keeps nekton small is the analogue of plankton's *opaque protocol*:

- nekton **carries** ontologies but **prescribes none**. A predicate/context is an opaque
  `TermRef`. Bring your own vocabulary.
- **Meaning and equivalence resolve downstream**, over the federated union of registries.
  "term A ≡ term B" is itself a signed claim - there is no kernel-level mapping table and no
  reasoner. (AAA: Anyone can say Anything about Any topic, signed.)

This is what stops nekton from growing into an ontology platform, exactly as the opaque
protocol stops plankton from growing back into the workbench.

## Non-goals (what nekton deliberately is **not**)

- **Not an execution or reasoning engine** - it records signed claims; it does not infer,
  evaluate, or reproduce them. Reasoners are external consumers.
- **Not an ontology** - it references terms; it defines and mandates none.
- **Not plankton** - it does not store files, fotons, or lineage; it points at them.
- **Not a trust policy** - *whose* signature counts is a cockpit/galaxy decision, outside the kernel.

## One-sentence form

> nekton is a minimal, ontology-agnostic, federated registry of DSSE-signed semantic
> commitments - extracted from plankton's attestation layer - that lets any cockpit attest
> reviews, validations, risk, votes, delegations, and equivalence about content-addressed
> things, with meaning resolved downstream rather than mandated by the kernel.
