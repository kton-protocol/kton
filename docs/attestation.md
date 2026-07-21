# Attestation - who brought in a ray, who confirmed it

> **This is the nekton layer.** Attestations were extracted from plankton into a separate
> protocol, **nekton** (DECISIONS §1–§5). The dividing invariant: a machine can *verify* a
> reproducible result (re-run / hash) → **plankton**; a person can only *vouch for* a statement
> (a signature) → **nekton**. Dependency is one-way: **nekton → plankton**, never the reverse.
> plankton records only fotons; the claims below (authored, confirmed, identity-equivalent,
> qualified, …) are **nekton claims** whose subject is a plankton hash. This doc is retained as
> the rationale + concept map; the normative contract is [`nekton/spec/SPEC.md`](../nekton/spec/SPEC.md),
> and a reference cockpit (**kton**) conducts both layers. The reasoning below is unchanged -
> only its home moved.

Files and fotons say *what happened*. Attestations add the **"who" and "why"** - the trust
layer. Two acts that must be kept distinct (and ideally performed by different parties):

- **Authored** - *who brought a ray in.* First-party: "I contributed this."
- **Confirmed** - *who verified a ray.* Third-party: "I checked it" / "I attest these two
  rays are identity-equivalent" / "I qualify this ray."

Separating author from confirmer is the GxP **four-eyes** principle and the basis of an
independent OQ.

## Ray

A **ray** is a connected subgraph (a path/DAG) of fotons - light travelling through the
graph: e.g. `data → F_est → {lst,ext} → F_so → SO → F_norm → canonical`. A **WebRay** is a
published, citable ray (a paper, F11). Attestations can target a single foton, a file, a
**ray**, or a **pair of rays**.

## The key point: confirmation is ray-level, not per-foton

Because equivalence is reached by *composing* normalization/comparator fotons, the
meaningful identity lives at the **ends of rays**, not at every intermediate foton. The
particular machine that ran an estimation, or the particular normalization invocation, are
incidental. So:

> You **confirm a ray** (or that **ray A ≡ ray B**), **not all the fotons** inside it.

A confirmer signs "these two rays converge to an equivalent endpoint under criteria C" - it
does not need to, and often cannot, vouch for each intermediate step independently.

## Attestation shape

```
Attestation := {
  subject:   Ref | [Ref, Ref],     # a foton, file, ray, OR a ray-pair (for identity)
  predicate: authored | confirmed | identity-equivalent | qualified | retracted | …
  by:        Agent,                 # org / person identity (cryptographic)
  when:      timestamp,
  why?:      Meaning,               # human reason (Part-11 signature meaning)
  evidence?: Ref,                   # e.g. the comparator verdict foton, criteria ids
  signature: Sig
}
```

nekton **stores and verifies** these claims; it does not produce them (the kernel signs-verifies
but never reasons). They are signed claims whose subject is a plankton hash (or another claim),
append-only. plankton itself never sees them - it records only fotons.

### The predicates that matter

| Predicate | Subject | Means |
|-----------|---------|-------|
| **authored** | foton / ray | "I brought this in" (submission provenance) |
| **confirmed** | foton / ray | "I verified this is valid" |
| **identity-equivalent** | **ray-pair** | "ray A ≡ ray B (endpoints converge under criteria C)" |
| **qualified** | ray | "this ray meets OQ criteria C" (the qualification verdict, signed) |
| **retracted** | foton / ray / attestation | "this is withdrawn / superseded" (immutability-safe correction) |

## How it lands on the Warfarin walkthrough

```
authored(F_est ray)            by: Uppsala (submitter)        ← brought the ray in
qualified(reproduction ray)    by: lab-QA                ← confirmed the OQ
  evidence: verdict foton (PASS@L2, criteria so-compare-v1)
identity-equivalent([ref_ray, repro_ray])  by: lab-QA, why: "OQ NONMEM 7.4.1"
```

Author (Uppsala) ≠ confirmer (QA): independent confirmation. The qualification is a
*signed attestation over a ray*, carrying its evidence (the verdict foton) and its criteria
ids - fully auditable.

## Requirements touched

These requirements are realised by the **nekton** layer (extracted from plankton), not by the
plankton kernel:
- **F7.4–F7.6** qualification verdicts are *confirmation claims* (nekton) - the mechanical L0/L1/L2
  comparison is a plankton `kind=compare` foton; its signed *acceptance* is a nekton claim.
- **F12** provenance/attestation layer - realised as nekton (`requirements.md`).
- **N3** GxP e-signatures: a nekton claim *is* an electronic signature (signer + meaning +
  timestamp), satisfying 21 CFR Part 11 §11.

## Cryptography - what we sign, and how

**Sign claims, not bytes.** Content-addressing already secures the bytes (the hash *is*
integrity). A digital signature adds what the hash cannot: **attribution** - *who vouches
for this*. So a publisher signs an attestation that *references hashes*, not the file
content itself.

```
            gives you        so you can…
  hash      integrity        trust the BYTES,  regardless of host
  signature authenticity     trust the CLAIM,  regardless of host
```

Both are host-independent - which is exactly why **federation and mirroring stay safe**: a
mirror carries a record by its content hash and re-derives its id on ingest (a tampered or
planted-id record is rejected), but it does NOT cryptographically check the signature - that
needs the signer's public key, which is the *consumer's* trust decision, not the mirror's.
The safety is that **anyone can verify the signature themselves** (`plankton verify` /
`nekton verify` with the signer's key), so you trust the *signature*, never the *mirror* (the
same move as "trust the hash, not the uri"). A mirror that copied a signature-invalid record
changes nothing: the invalid signature is caught the moment a consumer verifies it.

**Envelope.** Sign a **DSSE-style envelope** over the *literal payload bytes* (the in-toto
model). This separates two concerns that must not contaminate each other:
- foton **hashing** needs a canonical serialization (N6) for addressing/dedup;
- attestation **signing** signs the exact envelope bytes - no re-canonicalization at verify
  time.

**Identity.** Bind a signature to an accountable identity:
- **Org PKI / X.509** for regulated signers - a real person/org, with signing **meaning**
  and timestamp = a 21 CFR Part 11 electronic signature (non-repudiation).
- **Sigstore / Fulcio keyless** (OIDC-bound short-lived certs) for low-friction public
  federation; **DIDs** fit the self-hosted peer model.

**Transparency log** (Rekor-style, append-only): proves an attestation existed at time T
and was not backdated or secretly retracted - strong for public trust and GxP audit.

**Verify in kernel, trust by policy.** plankton verifies signatures cryptographically;
*whose* signatures count is galaxy/cockpit policy (F12.6). Key rotation/revocation: short-
lived certs + transparency log (valid-at-signing), or CRLs for long-lived org keys.

## Prior art

- **in-toto** - attestations about *who performed each step* in a supply chain, signed; the
  closest model for authored/confirmed step provenance.
- **SLSA provenance** + **DSSE** (Dead Simple Signing Envelope) - the envelope/format layer.
- **Sigstore/Rekor** - keyless identity-bound signatures + transparency log (tamper-evident
  attestation history).
- a modeling workbench's **review states** + Part-11 e-signatures - the precedent for
  author≠reviewer.

## Open questions

- Identity granularity: does an `identity-equivalent` attestation pin the *full* ray hashes,
  or just the endpoint pair + criteria? (Leaning: endpoint pair + criteria id; the rays are
  reachable in the graph.)
- Trust policy: whose confirmations count? (Per-galaxy policy; out of the kernel - the kernel
  stores + verifies signatures, cockpits decide whom to believe.)
- Revocation/retraction vs immutability (ties to N3 retention).
