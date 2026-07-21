# nekton kernel spec - 0.1 (draft, superseded)

> **Superseded by the unified kton specification** at [`../../spec/SPEC.md`](../../spec/SPEC.md) (v0.1),
> which covers both layers under the Community Specification framework. This file is retained as
> nekton-layer working notes; where the two disagree, the unified spec governs.

Normative-flavoured specification of the nekton kernel. Status: **v0 draft**, shape-compatible
with the plankton spec (same hashing, canonicalization, DSSE, federation). Rationale lives in
`../docs/`; this file is the contract two independent implementations must agree on.

Keywords MUST / SHOULD / MAY per RFC 2119.

## 0. Scope & conformance

nekton is a **commitment substrate**: it stores, verifies, indexes (by hash), and federates
**signed semantic claims**. It does **not** execute, reason over, or evaluate them, and it does
**not** define or mandate any ontology (those are consumers / external vocabularies).

A conforming implementation MUST:
- represent claims exactly as in §2–§3;
- accept and emit claims as in-toto Statements in DSSE envelopes (§3–§4);
- verify DSSE signatures (§4) and reproduce the §7 test vectors;
- expose the federation API (§6) over the union-by-hash resolution rule (§5);
- treat `predicate` and `context` as **opaque** `TermRef`s - it MUST NOT require, validate, or
  interpret any vocabulary (§2.2).

It MUST point at plankton objects only **by reference** and MUST NOT require any plankton
component to store or verify a claim (the dependency is nekton → plankton, resolved by cockpits).

The sole exception to "the kernel prescribes no grammar" is the structural scope/seed/chain grammar
of §5.5 - identity, order, boundary, nesting - which a conforming kernel MUST enforce. It remains
ontology-free.

## 1. Hashing & canonicalization

Identical to plankton §1 (shared primitive):
- content hash is **SHA-256**, written `"sha256:" + hex(lowercase)`; algorithm SHOULD be pluggable.
- **Canonical JSON**: UTF-8; object keys sorted by Unicode code point; no insignificant
  whitespace; no trailing newline (RFC 8785 JCS the SHOULD target).
- Canonical JSON is for **registry hashing/addressing only**; DSSE signs literal payload bytes
  (§4), keeping signing independent of canonicalization.

## 2. References

### 2.1 Ref - what a claim is about
```
Ref := {
  hash?: ContentHash,   # "sha256:…" - a plankton foton/ray/file, another claim id, or bytes
  uri?:  string         # an identity, term, or external resource
}
```
- At least one of `hash` | `uri` MUST be present. `hash` gives cross-registry recognition and
  verifiability; `uri` gives naming. Both = pinned + named.
- A `Ref.hash` MAY be a plankton object (foton, ray endpoint, file) or another nekton claim id
  (§3) - enabling **claims about claims**.

### 2.2 TermRef - the relation, opaque
```
TermRef := {
  hash?: ContentHash,   # content address of a term/definition (then the meaning is pinned), or
  uri?:  string         # a vocabulary IRI
}
```
- `predicate` and `context` are `TermRef`s. A conforming kernel MUST treat them as **opaque
  identifiers**: store, index, and federate them; **never** require a known vocabulary,
  validate term membership, or perform inference. Meaning resolves downstream (§8).

## 3. Claim (logical)

```
Claim := {
  subject:   Ref,                 # REQUIRED
  predicate: TermRef,             # REQUIRED
  object?:   Ref | Literal,       # OPTIONAL ; Literal := {value, datatype?:TermRef}
  context?:  TermRef,             # OPTIONAL scope/topic
  by:        Identity,            # REQUIRED ; = the signing key/identity (mirrors §4 keyid)
  when:      string,              # REQUIRED ; RFC 3339 UTC timestamp
  why?:      string,
  evidence?: [ Ref ]
}
```
- **Claim id** = `sha256(canonicalJSON(Claim))` *excluding* signature material (signatures live
  in the envelope, §4). Identical claims coincide by id.
- The claim is **constituted by its signature**. A claim carrying **no** signature is not a nekton
  claim and MUST be rejected on ingest. *Cryptographic* verification against a trusted key is an
  explicit act (`verify`) and a consumer/trust-policy concern (§4): the wire envelope carries a
  `keyid`, not the key, so the ingest fast-path cannot resolve and check every signature itself -
  it rejects the unsigned, and a mirror copies signatures for local re-verification ("mirroring ≠
  confirming"). This matches plankton.
- `object` MAY be omitted (unary predicates like `reviewed`, `confirmed`), a `Ref`, or a
  `Literal` (a value plus an optional datatype `TermRef`).

## 4. Wire form & signatures - claim as a signed in-toto Statement (DSSE)

Claims travel as **in-toto Statements** in **DSSE envelopes** - the *same* envelope as plankton
(shared trust layer), with a nekton predicate type.

### 4.1 `https://kton.dev/claim/v0`
```
subject:        [ { name?, digest?:{sha256}, uri? } ]   # the claim's `subject` Ref(s)
predicateType:  "https://kton.dev/claim/v0"
predicate: {
  predicate: TermRef,        # the relation (opaque)
  object?:   Ref | Literal,
  context?:  TermRef,
  by:        string,         # signer identity hint (authoritative identity = the §4 key)
  when:      string,
  why?:      string,
  evidence?: [ Ref ]
}
```
(Structurally: an in-toto Statement whose subject is the claim's subject and whose predicate is
the relation + object + provenance. A reviewer sign-off, a delegation, a `sameAs` mapping are
all this one shape with different `predicate` terms.)

### 4.2 DSSE envelope (identical to plankton §5)
```
Envelope := {
  payloadType: "application/vnd.in-toto+json",
  payload:     base64( canonicalJSON(Statement) ),
  signatures:  [ { keyid, sig } ]
}
PAE = b"DSSEv1 " + len(payloadType) + b" " + payloadType + b" " + len(payload) + b" " + payload
```
- Signatures over `PAE`. Default **Ed25519**; MAY support ECDSA/RSA.
- `keyid` = first 16 hex chars of `sha256(public_key_raw)`. `predicate.by` SHOULD agree with the
  signing key's bound identity; the **key is authoritative**.
- The kernel MUST NOT produce signatures, MUST reject an unsigned claim on ingest, and MUST be
  able to verify a signature on demand (`verify`) - where `verify` accepts an envelope carrying
  several signatures and succeeds if any verifies. *Which* keys/identities are trusted, for which
  predicates/contexts, is trust policy - out of the kernel. Mirroring copies claims with their
  original signatures (re-verifiable locally); it is not confirmation.
- **Identity**: keys SHOULD bind to accountable identities - org PKI/X.509 (= 21 CFR Part 11
  e-signature: signer + meaning + timestamp; `predicate.predicate` carries the *meaning*),
  and/or Sigstore-Fulcio (OIDC) / DIDs for open federation. A Rekor-style transparency log MAY
  anchor claims.
- **Trust policy** (whose signatures count, for which predicates/contexts) is OUT of the kernel.

## 5. Registry & resolution

A registry is a self-hosted **scope** of signed claims. No central registry.

- **Subject resolution:** the claims about a thing `H` are the visible claims whose `subject`
  digest/uri == `H`, over the **union of accessible registries**.
- **Claim-about-claim** chains resolve the same way (subject = a claim id).
- **Indexes** an implementation MUST provide (O(1) hash lookups):
  `by-subject → claims`, `by-predicate → claims`, `by-signer(keyid) → claims`,
  `by-object → claims`, `claim-id → claim`.
- Splicing across registries is by hash equality (automatic, verifiable).
- **Supersession/retraction** is an explicit claim (`predicate = supersedes`, subject = the
  superseded claim id); never deletion.

## 5.5 Scopes, seeds & the chain - the one structural grammar

This is the **only** grammar the kernel mandates. It concerns *structure* (identity, order,
boundary, nesting), never *meaning*. Rationale: `../docs/scopes-and-seeds.md`.

**Seed (scope genesis).** A Seed is a signed Statement with
`predicateType = "https://kton.dev/scope/v0"` and predicate fields:
```
{ scope: string, parent?: Ref, responsible: [Identity], genesis: true }
```
- A scope's **identity** is its Seed's content hash: `scope_id = sha256(canonicalJSON(Seed))`.
- A Seed MUST NOT carry `prev` (it opens the chain). `parent` is a Ref to the parent scope's
  Seed hash, omitted only for a root scope.
- `genesis: true` is admissible ONLY on a Seed: a conforming kernel MUST reject `genesis: true`
  on any Statement whose `predicateType` is not `https://kton.dev/scope/v0`. This is the
  converse anti-forgery check - a non-seed cannot claim to open a chain.

**Chain.** Every non-genesis Statement that belongs to a scope MUST carry `scope` (= the
`scope_id`) and `prev` (the hash of the immediately preceding Statement *in that scope*). Removal or
reordering breaks the chain and MUST be detectable - this is the tamper-evidence ("untainted")
guarantee. *(Superseded: this file's earlier "MUST verify on ingest that the chain reaches `scope_id`
without a gap" is corrected by the unified [`spec/SPEC.md`](../../spec/SPEC.md) §7.4 - ingest is
**monotone**: a scoped claim with an unresolved `prev` is ACCEPTED and deferred, not rejected, and
seal-verification is a consumer check over the resolved union. The reference implementation follows the
unified spec.)*

**What the kernel enforces:** identity (`scope_id` = seed hash), order (the `prev` chain),
boundary (a statement's `scope`), nesting (`parent`). Nothing else.

**What stays convention (NOT kernel):** the meaning of `responsible`, the `registers-scope`
trust-transfer statement a parent records about a child, and sealing rules (e.g. all-responsible
must sign a seal) are checked by **consumers / aggregator executors**, not the kernel. The kernel
treats `responsible` as an opaque list it stores; it does not require registration or sealing.

**Predicate names remain opaque.** The kernel understands the *structural* fields `scope`,
`parent`, `prev`, `genesis`, `responsible`. It still does not interpret predicate/context terms
(§2.2) - `registers-scope`, `vote-initialised`, `count-finished` are vocabulary (templates), not
kernel meaning.

## 6. Federation API (minimum surface)

Over HTTP(S) (binding MAY vary). Public endpoints expose only the public scope.

| Op | Returns |
|----|---------|
| `GET claims?subject=H` | claims whose subject == H |
| `GET claims?object=H` | claims whose object == H |
| `GET claims?signer=K` | claims signed by keyid K |
| `GET claims?predicate=P` | claims with predicate term P (opaque match) |
| `GET claim?id=C` | a single claim Statement + envelope |
| `GET mappings?term=T` | claims relating term T to others (`sameAs`/`broaderThan`/…) - for downstream resolution |
| `GET sync?since=T` | append-only claims since cursor T (set reconciliation) |

- Records are immutable + content-addressed ⇒ `sync` is conflict-free set union;
  **mirroring** = `sync` + persistence. Because a batch may deliver a scoped child before its
  seed, ingest **settles** scoped claims in dependency order (a child waits for its seed/`prev`)
  and **skips** records that never become valid; the peer cursor always advances, so one
  malformed or hostile record cannot permanently wedge replication.
- The kernel serves claims and term-mapping claims; it MUST NOT perform inference over them
  (that is a consumer concern, §8).

## 7. Conformance test vectors

The normative vectors are **frozen** in [`../reference/testdata/`](../reference/testdata/) with
deterministic test keys (ed25519 seeds derived from fixed public labels; only the public `.pub`
keys are committed) and regenerated by `go run ./testdata/gen` from the `reference` module dir. CI
fails on drift (`../reference/claim/vectors_test.go`), exactly as plankton freezes its foton vectors
(plankton SPEC §15). Each vector is a human-readable `*.statement.json` source and its signed
`*.dsse.json` envelope; the `claim id` is the SHA-256 of the canonical Statement (§3):

| Vector (`statement` + `dsse`) | Signer key | `claim id` |
|-------------------------------|------------|------------|
| `reviewed` — a `confirmed` review sign-off (four-eyes) | `reviewer.pub` | `sha256:9913d1c7d5460ee09759eccfe77eccdcf3d1b5458fc0c9c9e5577532e545c0ab` |
| `delegate` — a governance delegation claim | `chair.pub` | `sha256:cf18b528cabb0a033c3dcb76b56b7ac10aaa02a0c10b5fc2f21b4b022f048969` |
| `sameas` — a `sameAs` term-mapping claim | `curator.pub` | `sha256:ed75d8ad311a904cc9408cdcd74b3045e7e8e9fdee5f00d01449c2273aa01b36` |
| `foton-subject` — subject is a plankton foton hash (cross-layer splice) | `reviewer.pub` | `sha256:f74b5a76b02f7dd9d016d591459a35c4d848d3e7baf2269ebd448d492455792b` |

The `foton-subject` vector's `subject` digest is the frozen plankton foton id
`sha256:5da55d7885d87097e5decf17d7edf6e49597a655f401249cca66bd77a17121f1` (plankton SPEC §15), so a
`subject = <plankton foton hash>` lookup splices the two layers by hash equality alone.

A conforming implementation MUST: recompute each `claim id` above; verify the DSSE signature against the
published public key; reject a one-byte-tampered payload; index the claim by subject/predicate/signer/object;
and resolve a `subject = <plankton foton hash>` lookup without holding any plankton component.

## 8. Out of scope (normatively NOT the kernel)

Ontology definition; equivalence reasoning / inference; vote & delegation **tallying** (a
deterministic plankton foton + a cockpit); trust policy; key lifecycle/PKI; UI. nekton stores,
signs-verifies, indexes, and federates claims - and stops there. See `../docs/charter.md` non-goals.

## 9. Versioning

- Predicate type is versioned in its URI (`/v0`, `/v1`, …).
- This spec is **v0**: shapes may change before v1. The invariants (one signed `Claim` type;
  opaque `Ref`/`TermRef`; DSSE-signed; federated by hash; ontology-agnostic; nekton → plankton
  by reference) are stable.
