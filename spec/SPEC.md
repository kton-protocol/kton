# kton - a content-addressed provenance protocol

### Version 0.1
### Status: 0.1 (draft)

© 2026 Michael Hackl

This specification is subject to the **Community Specification License 1.0**, available at
[../community-specification/01-community-specification-license-v1.md](../community-specification/01-community-specification-license-v1.md).
Its scope and governance are in [../community-specification/](../community-specification/).

---

## Foreword

kton specifies a minimal, transport-neutral protocol for **content-addressed data provenance**: a
format and a set of verification semantics for recording *how a result was produced* (the **plankton**
layer) and *what has been attested about it* (the **nekton** layer), such that any party can re-derive
and independently verify those records **without trusting their producer**.

This document unifies and supersedes the earlier layer-specific drafts (`../nekton/spec/SPEC.md` and
prior revisions of this file), which are retained only as working notes. Where this document and those
disagree, this document governs.

Drafted following ISO standard conventions (per the Community Specification template) to ease a later
transition to a formal standards body. Clauses are **normative** unless marked *(informative)*.
Sections still hardening at 0.1 are marked *(0.1 - subject to change)*.

## Introduction

A kton record is a signed statement over content hashes. Two records with the same content have the
same identity; a record whose bytes were altered after signing does not verify; a reference to content
that does not hash as claimed does not resolve. From these three properties everything else follows:
lineage is a hash join, federation is a conflict-free union, and trust is a matter of *which keys a
consumer chooses to believe* - never of a central authority. The protocol **documents; it never
executes**.

## 1 Scope

This specification defines:

- the **canonicalization** and **content-addressing** rules by which record identity is computed
  (Clause 5); <!-- scope:in canonicalization -->
- the **plankton** result format - `FileRef`, `Foton`, action key, potentials, optional environment -
  and its wire form (Clause 6); <!-- scope:in plankton-format -->
- the **nekton** attestation format - `Ref`, `TermRef`, `Claim`, and the scope/seed/chain grammar -
  and its wire form (Clause 7); <!-- scope:in nekton-format -->
- the shared **signature and identity** model (Clause 8), including where external verification
  material - identity and time evidence produced by other schemes - attaches (Clause 8.1);
  <!-- scope:in signing-model --> <!-- scope:in verification-material -->
- **reproduction and normalization** semantics (Clause 9) and **tool/environment qualification**
  (Clause 10); <!-- scope:in reproduction --> <!-- scope:in tool-qualification -->
- **registry resolution** and the completeness/validity distinction (Clause 11), **federation and
  aggregation** (Clause 12), and **conformance** (Clause 15).
  <!-- scope:in registry-resolution --> <!-- scope:in federation -->

The following are **out of scope** (implementation choices; no patent commitment attaches):
specific transports and hosting (git, GitHub, HTTP, object stores) <!-- scope:out transports -->;
specific signing backends (Sigstore, RSA/nanopublication, a particular transparency log, an eIDAS
trust service) <!-- scope:out signing-backends --> and the evaluation of any evidence they produce
<!-- scope:out evidence-evaluation -->; **document-rendered signature forms** such as signed PDFs,
which sign a rendering rather than the record and are therefore projections (Clause 14, and 8.1)
<!-- scope:out document-rendered -->; specific tools, executors, and cockpits
<!-- scope:out tools-and-cockpits -->; and the reference source code (licensed separately,
Apache-2.0) <!-- scope:out reference-code -->.

The **patent** Scope of this Working Group - what the Community Specification License commits - is
defined by `../community-specification/02-scope.md`, not by this clause. The two are deliberately
kept in step and `scripts/check-scope-drift.sh` fails CI if they diverge, but they answer different
questions: this clause says what *this document* specifies, that file says what the commitment
covers.

A conforming implementation MUST NOT require any particular cockpit, executor, transport, or hosting
provider, and MUST NOT execute the protocols, normalizers, or tools that records describe.

## 2 Normative references

- **RFC 2119 / RFC 8174** - keywords MUST, MUST NOT, REQUIRED, SHALL, SHOULD, MAY, OPTIONAL.
- **RFC 8785** - JSON Canonicalization Scheme (JCS).
- **RFC 4648** - Base64.
- **RFC 3339** - date/time on the Internet (timestamps).
- **in-toto Attestation Framework v1** - the Statement envelope shape.
- **DSSE** (Dead Simple Signing Envelope) - the signing envelope and PAE.
- **Multihash** - the self-describing hash convention (`sha256:` prefix).
- **FIPS 180-4** - SHA-256.

## 3 Terms and definitions

- **content hash** - the SHA-256 of a byte string, written `"sha256:" + hex` (lowercase).
- **canonical JSON** - the byte-exact JSON form defined in Clause 5.
- **FileRef** - a reference to a file by content hash (Clause 6.1).
- **foton** - a transformation edge: input tree → protocol → output tree (Clause 6.2).
- **action key** - the identity of a *computation* (inputs + protocol), independent of outputs (6.3).
- **potential** - a foton with unbound slots; a template/normalizer definition (Clause 6.4).
- **claim** - a signed subject–predicate–object attestation (Clause 7.2).
- **scope / seed** - the structural chain grammar for accountable claim ordering (Clause 7.4).
- **spectrum** - the object that defines a tool or environment by a reference foton set (Clause 10).
- **reproduction level** - L0 byte-identical / L1 canonical-identical / L2 within-tolerance (Clause 9).
- **kernel** - an implementation of the record layer itself: canonicalization, identity, storage,
  indexing, resolution and verification. Requirements addressed to "a conforming kernel" bind that
  layer, whether it ships as a library or behind a command-line tool. A *cockpit* (a tool that
  drives a kernel), an *executor* and an *aggregator* are not kernels.
- **aggregator** - a discovery index over records; not a store and not a trust anchor (Clause 12).
- **verification material** - external evidence *about* a record - who signed it, or that it existed
  by a given time - bound to the record by its content address and opaque to the kernel (Clause 8.1).

## 4 Conventions

Key words are per RFC 2119/8174. A **conforming implementation** is one that satisfies every MUST and
MUST NOT in Clauses 5–15. `object.field` denotes JSON member access. `sha256(x)` denotes the content
hash of byte string `x`. `canon(v)` denotes the canonical JSON encoding (Clause 5) of value `v`.

## 5 Content addressing and canonicalization  *(interoperability core - highest priority)*

Canonicalization is the single most interoperability-critical part of this specification: two
independent implementations MUST compute the **same** hash for the **same** content, and they can only
do so if the canonical byte form is exact.

5.1 The content hash function is **SHA-256**. A content hash is the ASCII string `"sha256:"` followed
by the lowercase hex encoding of the 32-byte digest. Implementations SHOULD keep the algorithm
identifier pluggable for future agility, but MUST emit and accept `sha256:` at 0.1.

5.2 A **file's** content hash is computed over its uncompressed byte content.

5.3 **Canonical JSON** is defined as **RFC 8785 (JSON Canonicalization Scheme, JCS)**. A conforming
implementation MUST canonicalize per RFC 8785 before hashing, and SHOULD use a tested JCS
implementation rather than a hand-rolled serializer or a `JSON.stringify`-style encoder, which are not
JCS-conformant at the edges. The rules are restated here so this specification is self-contained and
testable (see the conformance tests in `../reference/core/canon_test.go`):

- **Numbers** MUST be serialized by the ECMAScript Number-to-String algorithm (RFC 8785 §3.2.2.3):
  shortest round-tripping IEEE-754 double form, lowercase `e`, explicit `+` on positive exponents, no
  trailing zeros - e.g. `4.50` → `4.5`, `1E30` → `1e+30`, `2e-3` → `0.002`, `1.0` → `1`. **A value that
  needs more precision or range than an IEEE-754 double can hold - a high-precision measurement, a large
  integer id, an exact decimal - MUST be carried as a JSON string, never a JSON number.** This is a
  schema-design rule, called out where plankton/nekton fields are defined, not merely a serialization
  rule.
- **Strings** MUST be escaped per RFC 8785 §3.2.2.2: control characters below U+0020 use the five named
  short escapes (backspace, tab, line-feed, form-feed, carriage-return) or otherwise a **lowercase**
  four-hex-digit escape; above U+0020 only the double-quote and the backslash are escaped; every other
  character - including all non-ASCII and the forward slash - is emitted literally as UTF-8. (Uppercase
  hex, escaping non-ASCII, or escaping `/` each produce different bytes and break interoperability.)
- **Object member names** MUST be sorted by their UTF-16 code units; **array element order MUST be
  preserved** - never sorted, because order is data (a reproduction chain, a list of parents).
- No insignificant whitespace; `null` / `true` / `false` serialized as those tokens.
- Input MUST conform to I-JSON (RFC 7493): no duplicate member names; valid Unicode; and **no Unicode
  normalization is applied** - strings differing only in composition form (NFC vs NFD) are different
  content and hash differently.

Canonicalization fixes the byte representation, not the meaning: parsing canonical bytes back yields the
same logical value. It is the technical floor under kton's truth-coupling - without "same content →
same bytes → same hash" holding across independent implementations, "well-formed ⇒ verifiable across
strangers" cannot hold.

*(0.1 limitation: the reference implementation hard-rejects duplicate member names and
non-double-representable integers, but routes values through the platform JSON layer, which
**deterministically** replaces invalid UTF-8 with U+FFFD instead of erroring as strict I-JSON requires,
and does not yet hard-reject lone surrogates. This affects only malformed input; well-formed records are
fully JCS-conformant and the conformance vectors verify byte-for-byte.)*

5.4 **Record identity** (foton id, claim id, `scope_id`, `protocol.ref`, action key) is `sha256(canon(
…))` over the indicated value. **Identical content coincides**: two records whose canonical forms are
equal have the same identity, regardless of cosmetic input differences (member order, whitespace, line
endings). *(This is the requirement Scenario 1, "The Misunderstanding," tests.)*

5.5 Canonical JSON is used for **identity and addressing only**. It MUST NOT be relied on for
signatures: signatures are computed over literal payload bytes (Clause 8), keeping the trust layer
independent of canonicalization.

5.6 **Hash binding.** Wherever a record references content by hash, a consumer that fetches bytes for
that hash MUST reject them if their SHA-256 does not equal the referenced hash. Trust the hash, not the
host. *(Scenario 2 / Scenario 8.)*

## 6 The plankton layer - results

### 6.1 FileRef

A reference to a file. The protocol stores **no bytes**.

```
FileRef := {
  hash?:      ContentHash,   # present = BOUND; ABSENT = an unbound slot (6.4), keyed by `path`
  path?:      string,        # RELATIVE path within the foton work tree, e.g. "raw/data.csv"
  id?:        string,        # OPTIONAL persistent/local identity      (reserved at 0.1 - see below)
  uri?:       [ string ],    # OPTIONAL location hints (carried, not covered)
  mediaType?: string,        #                                         (reserved at 0.1 - see below)
  meta?:      object         #                                         (reserved at 0.1 - see below)
}
```

- Identity and integrity derive from `hash`. `uri`, `id`, `mediaType`, and `meta` are **carried, not
  covered**: they are location/description hints and MUST NOT affect any identity computation (foton id
  or action key). A consumer MUST verify fetched bytes against `hash` (5.6).
- **Wire transport at 0.1.** Of the carried fields, only `uri` is emitted onto the wire (6.6) and
  round-tripped by a conforming implementation at 0.1. `id`, `mediaType`, and `meta` are **reserved**:
  defined for forward compatibility but NOT yet emitted or parsed, and a conforming implementation MAY
  ignore them. (The reference `FileRef` type declares `id`/`mediaType` and omits `meta` accordingly.)
  Transporting them is a later-revision addition; because they are non-covered, adding them will not
  change any existing foton id or action key.
- `path` is **structural** - tools depend on layout - and is part of foton identity and the action key
  (6.3). Absolute paths and the execution sandbox root are incidental and MUST NOT be recorded.
- A FileRef with no `hash` (path only) is an **unbound slot** (6.4).

### 6.2 Foton

```
Foton := { inputs: [FileRef], outputs: [FileRef], protocol: Protocol }
Protocol := {
  kind:        string,       # e.g. "nonmem","r","normalize","compare"
  ref:         ContentHash,  # = sha256(canon(descriptor)) when descriptor present
  descriptor?: object        # opaque to the kernel; interpreted only by external executors
}
```

- `protocol.ref` MUST equal `sha256(canon(descriptor))` when `descriptor` is present.
- The descriptor is **opaque**: a conforming kernel MUST NOT interpret it.

### 6.3 Action key and foton id

- **action key** = `sha256(canon({ inputs: {relpath → hash}, protocol: P }))`, the identity of the
  *computation* (inputs and protocol only; outputs are NOT included). Two fotons with equal action key
  describe the same computation. The preimage MUST be formed as follows:
  - **inputs** — the `{relpath → hash}` map. Two inputs sharing a `relpath` with different hashes MUST be
    rejected: the map cannot hold both, and a silent last-wins would erase an input from the computation
    identity (letting a 2-input foton falsely reuse a 1-input result).
  - **protocol `P`** —
    - when a `descriptor` is present, `P = { kind, ref }` and `ref` MUST be the **effective ref**,
      `sha256(canon(descriptor))` recomputed from the carried descriptor (6.2) — never a self-declared
      `ref` that disagrees with it;
    - when **no** `descriptor` is present (a bare, unverifiable `ref`), `P = { kind, ref, refUnverified: true }`.
      The `refUnverified: true` marker MUST be present in this case, so a descriptor-less foton can never
      share an action key with a descriptor-ful foton whose descriptor happens to hash to the same `ref`.
      (Without it, an attacker's descriptor-less foton asserting `ref = sha256(canon(victim descriptor))`
      would collide with — and poison the cache of — the victim's verifiable computation.)
- **foton id** = `sha256(canon(Foton))`. Carried, non-covered FileRef fields (6.1) MUST NOT change it.

### 6.4 Potentials

A **potential** is a foton with unbound slots - input *holes* and/or *virtual outputs* (FileRefs
lacking `hash`). It is a definition (a template; a **normalizer** is one), not an execution. A
conforming kernel MUST canonicalize unbound slots by `path` (omitting `hash`), give the potential a
stable foton id, and MUST NOT realize it. An external executor realizes a potential by binding its
holes and producing its declared virtual outputs; a realized (fully bound) foton is a distinct record.

### 6.5 Execution environment *(optional)*

How a foton was produced MAY be recorded, executor-agnostically, in two independent OPTIONAL parts:

- **env-spectrum reference - COVERED.** `protocol.descriptor.environment` MAY be a `SpectrumId`
  (Clause 10) naming an environment class the producer claims to satisfy. Because it lives inside the
  descriptor, it is part of `protocol.ref` and therefore the action key and foton id: a foton produced
  "under a qualified-X environment" is a distinct computation. It names a *qualification*, not an image.
- **concrete env-data - CARRIED, not covered.** `EnvData := [{ kind, ref, locators? }]` (e.g.
  `oci`/`nix`/`renv`) records the exact stack for reconstruction. It MUST NOT affect any identity.

A concrete environment is bound to an env-spectrum by a nekton `qualifies-as` claim (7.2): mechanically
the environment *fulfils* the spectrum (Clause 10); acceptance as qualified is a signed claim on top.

### 6.6 Wire form - foton as an in-toto Statement

A foton travels as an in-toto Statement (`_type = "https://in-toto.io/Statement/v1"`) with
`predicateType = "https://kton.dev/foton/v0"`:

```
subject:            outputs            # [{ name, digest: {sha256} }]
predicate.inputs:   [ {name, digest} ] # materials / dependencies
predicate.protocol: { kind, ref, descriptor? }
```

The kernel records exactly **one** plankton predicate type - the foton. Signed statements *about*
fotons are nekton claims (Clause 7). The mechanical L0/L1/L2 comparison of two results is itself a
foton (`protocol.kind = "compare"`); its **acceptance** is a nekton claim (Clause 9).

## 7 The nekton layer - attestations

### 7.1 Ref and TermRef

```
Ref     := { hash?: ContentHash, uri?: string }   # at least one present
TermRef := { hash?: ContentHash, uri?: string }   # the relation/context, opaque
```

- A `Ref.hash` MAY address a plankton object (foton, file) or another claim id - enabling claims about
  claims.
- `predicate` and `context` are `TermRef`s. A conforming kernel MUST treat them as **opaque
  identifiers**: store, index, and federate them, and MUST NOT require a known vocabulary, validate term
  membership, or perform inference. Meaning resolves downstream.

### 7.2 Claim

```
Claim := {
  subject:   Ref,                # REQUIRED
  predicate: TermRef,            # REQUIRED
  object?:   Ref | Literal,      # OPTIONAL ; Literal := { value, datatype?: TermRef }
  context?:  TermRef,            # OPTIONAL
  by:        Identity,           # REQUIRED label; NOT key-bound - the §8 keyid is authoritative
  when:      string,             # REQUIRED ; RFC 3339 UTC
  why?:      string,
  evidence?: [ Ref ]
}
```

- **claim id** = `sha256(canon(Claim))`, excluding signature material (signatures live in the envelope).
- A claim is **constituted by its signature**: a claim carrying no signature is not a nekton claim and
  a conforming kernel MUST reject it on ingest.
- **`by` is a self-asserted label, not a proof of identity.** It is covered by the signature (so it
  cannot be altered after signing), but the kernel does NOT enforce that it matches the signing key -
  the authoritative identity is the **keyid** (§8). A consumer that trusts a named identity MUST check
  the keyid, not `by`; a reader SHOULD present the proven keyid at least as prominently as `by`.
- `object` MAY be omitted (unary predicates such as `reviewed`), a `Ref`, or a `Literal`.
- **Directional object-refs.** When `object` is a `Ref.hash`, the claim asserts a directional relation
  from `subject` to `object` (e.g. `reproduces`, `refines`, `qualifies-as`). The kernel stores the
  direction; it does not interpret the predicate.

### 7.3 Wire form

A claim travels as an in-toto Statement with `predicateType = "https://kton.dev/claim/v0"`, its
`subject` being the claim's subject Ref(s) and its `predicate` carrying `{predicate, object?, context?,
by, when, why?, evidence?}`. A reviewer sign-off, a delegation, and a `sameAs` mapping are all this one
shape with different `predicate` terms.

### 7.4 Scopes, seeds, and the chain - the one structural grammar

This is the **only** grammar the kernel mandates. It concerns *structure* (identity, order, boundary,
nesting), never meaning.

- **Seed.** A seed is a signed Statement with `predicateType = "https://kton.dev/scope/v0"` and
  predicate `{ scope, parent?, responsible: [Identity], genesis: true }`. A scope's identity is
  `scope_id = sha256(canon(Seed))`. A seed MUST NOT carry `prev`. `genesis: true` is admissible ONLY on
  a seed: a conforming kernel MUST reject `genesis: true` on any non-`scope/v0` statement.
- **Chain.** Every non-genesis statement belonging to a scope MUST carry `scope` (= the `scope_id`) and
  `prev` (the hash of the immediately preceding statement in that scope). **Ingest is monotone:** a
  well-formed, signed scoped statement is accepted even if its `prev` is not yet resolvable (it may live
  in another source; Clause 11). The closed-world guarantee - that the chain reaches `scope_id` without a
  gap - is a **seal-verification** judgment, evaluated over the resolved union of sources *when the seal
  is relied upon*, NOT an ingest-time rejection. Removal or reordering then breaks the chain and MUST be
  detectable. *(Scenario 5 / Scenario 2; see Clause 11, Monotonicity.)*
- **What stays convention (NOT kernel):** the meaning of `responsible`, parent→child registration, and
  sealing rules are checked by consumers/aggregators, not the kernel.

## 8 Signatures and identity (DSSE) - shared trust layer

Every plankton and nekton Statement is published as a signed DSSE envelope. This is the *same* envelope
for both layers.

```
Envelope := { payloadType: "application/vnd.in-toto+json",
              payload:     base64(canon(Statement)),
              signatures:  [ { keyid, sig } ] }
PAE = "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
```

- Signatures are computed over `PAE`. Default algorithm **Ed25519**; an implementation MAY support
  ECDSA/RSA.
- `keyid` = first 16 hex chars of `sha256(public_key_raw)`.
- **The envelope's `keyid` is a self-reported hint, not a proof.** It is not covered by the signature,
  so it can be forged; the *authoritative* signer keyid is the one derived from a key that actually
  verifies. `verify` MUST report the **verifying** key's keyid on success (and SHOULD flag a declared
  keyid that differs from it); a reader MUST NOT present an unverified declared keyid as authoritative.
- A conforming kernel MUST be able to verify a signature on demand (`verify`, which succeeds if **any**
  of an envelope's signatures verifies). It MUST NOT sign on **ingest**, MUST NOT hold or manage signing
  keys, and MUST NOT add a signature its caller did not ask for. Offering a signing helper to a caller
  that holds its own key is permitted and expected; a kernel SHOULD additionally expose the two halves
  separately - the bytes to be signed, and a seal that takes a signature back - so that a caller signing
  in a browser, a smartcard or an HSM never hands the kernel a private key at all. It does **not** verify
  signatures on **ingest**: the wire carries a `keyid`, not the key, so ingest cannot check a signature
  - it rejects *unsigned* claims (§7.2) but stores signed ones unverified. Trust is conferred only by an
  explicit `verify` against a key the consumer chooses (trust policy, below). An index / `show` entry
  therefore means "a claim signed by *some* key exists," not "verified" - mirroring ≠ confirming.
- **Tamper-evidence (Scenario 2).** A signature that does not verify against the presented payload bytes
  MUST be reported as invalid. An implementation SHOULD distinguish *wrong key* (the signer's key was
  not supplied) from *tampered* (the supplied key is the signer's, but the bytes no longer match) - the
  first is a key-resolution problem, the second is an integrity failure.
- **Identity (Scenario 4).** The attestant's identity is the signing key, readable via `keyid`.
  *Whether* an attestant is a human or a specific agent/model session is a property of the **identity
  bound to that key**, resolvable from the key's accountable identity (org PKI/X.509 for regulated
  signers - a 21 CFR Part 11 e-signature is signer + meaning + timestamp; Sigstore-Fulcio/OIDC or DIDs
  for open federation). It is NOT a pre-assigned record role. Keys SHOULD bind to accountable
  identities. Ephemeral signing is permitted - a throwaway key whose `by` label need not identify a
  person - so a record can be unlinkable to any accountable identity; trust then rests on re-running
  the record, not on the signer. (`by` remains a required field; anonymity lives in the *key*, not in
  omitting the label.)
- **Trust policy** - *which* keys/identities count, for which predicates/contexts - is OUT of the
  kernel (a cockpit/consumer concern).

### 8.1 Attached verification material *(0.1 - new)*

The DSSE signature proves that *some key* signed the payload. It does not carry what a reader needs to
decide **whose key that was**, nor that the record existed at a given time. A short-lived Sigstore
certificate, a transparency-log inclusion proof, an X.509 chain from an organisation's PKI, a
qualified certificate under eIDAS, an RFC 3161 timestamp token - §8 and §13 both call for these, and
none of them has anywhere to live. This clause gives them one.

```
VerificationMaterial := { subject:   "sha256:<hex>",
                          scheme:    <token>,
                          mediaType: <media type>,
                          material:  base64(<the scheme's own artifact>) }
```

- **`subject` MUST be the record's content address** - a foton id or a claim id. Because a claim id is
  `sha256(canon(Statement))` and the envelope's `payload` *is* those canonical bytes, a scheme that
  signs bytes MUST sign the canonical Statement bytes. The binding is then **structural**: the digest
  the external scheme committed to *is* the record's identity. It MUST NOT rest on a filename, on a
  particular serialization of the envelope, or on co-location.
- **The kernel MUST NOT interpret or verify `material`.** This is the §8 posture exactly: stored is not
  verified. A kernel carries verification material as opaque bytes; evaluating it - and deciding which
  issuers, trust lists or identities count - is a consumer concern, like trust policy.
- **Presence, absence, or invalidity MUST NOT affect the record's validity or resolvability** (§11).
  Verification material is evidence *about* a record, never a precondition of it. A registry that
  cannot read a material MUST still resolve the record.
- **Several are permitted per record**, and they answer different questions: an identity witness
  (*who stands behind this*), a time witness (*that it existed by then*), and a legally qualified
  signature are independent and MAY coexist.
- **An unrecognised `scheme` MUST be carried, not rejected.** Refusing unknown evidence would make the
  set of schemes a protocol version, which is precisely what this clause exists to avoid.

Initial scheme tokens (the list is open; registration is out of scope for 0.1):

| `scheme` | typical `mediaType` | answers |
|---|---|---|
| `sigstore-bundle` | `application/vnd.dev.sigstore.bundle.v1+json` | who (OIDC identity via Fulcio) |
| `rekor-entry` | `application/json` | when (transparency-log inclusion, §13) |
| `rfc3161` | `application/timestamp-reply` | when (qualified timestamp) |
| `cms-detached` | `application/pkcs7-signature` | who (X.509: organisation PKI, smartcard, detached CAdES) |
| `jades` | `application/jose+json` | who (the eIDAS JSON signature form) |
| `pgp-detached` | `application/pgp-signature` | who |

**Document-rendered signature forms (e.g. PAdES / signed PDFs) are OUT of scope.** They sign a
*rendered* representation of a record, and the relationship between that rendering and the canonical
bytes is not content-addressed - a second representation free to drift from the first. §14 already
draws this line for publication projections and requires an explicit provenance reference rather than
assumed hash equality. A signed document is therefore a §14 projection, and its signature stands over
the projection, not over the record.

## 9 Reproduction and normalization

A reproduction is expressed as a `compare` foton (6.6) over `(reference, candidate, criteria)` inputs,
and its acceptance as a nekton claim.

- **Reproduction levels:** **L0** byte-identical; **L1** canonical-identical after a declared
  normalizer; **L2** within a declared numeric tolerance.
- **A reproduction claim MUST carry its level and its normalization.** A claim asserting that a result
  reproduces another, without stating the comparison level (and, for L1, the normalizer potential it was
  compared under), is **ill-formed** and a conforming consumer MUST reject it as such. "Reproduced"
  alone is not a well-formed statement. *(Scenario 6.)*
- Normalization is itself a **potential** (6.4) applied by an external executor and recorded as a linked
  foton; the normalized output is referenced by hash. A normalizer used to qualify other tools MUST
  itself be qualified at L0 (byte-exact re-run) before its outputs are trusted. This is a **consumer
  obligation**: the kernel renders the mechanical L1 match but does not gate on the normalizer's own
  qualification, so a conforming consumer MUST establish it (e.g. ≥2 verified producers of the
  normalizer's output, or a spectrum) before relying on an L1 result. The reference `plankton reproduces
  --via` surfaces this obligation on every L1 result.

## 10 Tool and environment qualification - Spectrum

A **spectrum** defines a tool (or an execution environment) structurally - by a reference foton set plus
an optional normalizer - so it belongs in the protocol.

```
Spectrum := { spectrum: string, of?: string, normalizer?: PotentialId,
              members: [ { name, output: sha256, model?: Ref, data?: Ref } ] }
```

- A candidate **fulfils** a spectrum iff it reproduces **every** member of the reference set (raw-equal,
  or equal after following the declared normalizer). **Partial fulfilment is non-fulfilment**: a
  conforming `spectrum check` MUST refuse qualification if any member is not reproduced. *(Scenario 7.)*
- `spectrum check` compares fotons that already exist; the kernel runs neither the tool nor the
  normalizer and renders **no verdict**. Whether fulfilment is *named* (e.g. "validated at L1") and
  whether a human *accepts* it as a qualified tool is a signed nekton claim on top of these facts.
- The same object qualifies an **environment** (6.5): a foton's `protocol.descriptor.environment`
  references such a spectrum; a concrete stack is bound to it by a `qualifies-as` claim once it fulfils.

## 11 Registry, resolution, and completeness

A registry is a self-hosted scope of records. There is no central registry.

- **Lineage** of a file hash `H` is the visible foton(s) whose `subject` contains `H`, resolved over the
  **union of accessible registries**. A hash with no visible producer is a lineage root.
- **Subject resolution** for claims (including claims-about-claims) resolves the same way.
- A conforming implementation MUST provide O(1) hash indexes: for plankton `by-output-hash`,
  `by-input-hash`, `by-action-key`, `id → object`; for nekton `by-subject`, `by-predicate`,
  `by-signer(keyid)`, `by-object`, `claim-id → claim`.
- **Completeness vs validity (Scenario 9).** A record that references a parent/subject which cannot be
  resolved is **incomplete**, NOT invalid. A conforming implementation MUST still verify such a record's
  own content and signature, and MUST distinguish "a referenced object cannot be resolved" (an
  incomplete chain) from "this record is invalid" (a failed hash or signature). A dead link elsewhere
  MUST NOT invalidate an otherwise-sound record.
- **Retraction/supersession** is an explicit claim (`predicate = supersedes`/`retracted`, subject = the
  superseded record), never deletion.
- **Monotonicity (the substrate invariant).** A record's **validity is intrinsic** - determined by its
  own hash and signature alone, checkable locally and independent of any source list. Its
  **resolvability** (whether referenced parents/subjects are found) is relative to the sources read.
  Adding a source can only **add**: it may surface more records and resolve more references, but MUST
  NOT make a valid record invalid or retract a statement. Two readers with different source lists
  therefore reach the **same validity judgment** on a record and may differ only in what they can
  resolve. (This is why "incomplete" MUST NOT be conflated with "invalid" above, and why retraction is
  additive.)
- **The two deliberate closed worlds.** Exactly two operations introduce a closed world over this
  monotone substrate, and **both carry that world in a signature**:
  1. a **sealed scope** (7.4) is a *defined*, not discovered, world - its seed fixes membership, its
     head seals order; a gap is fatal, but as a **seal-verification** check over the resolved union, not
     an ingest rejection.
  2. a **gate/verdict** is the only **non-monotone** operation - one more source can surface a reject
     and flip pass->fail - so a verdict MUST carry its **corpus** (the signed list of sources it was
     decided over) inside its signed payload. A verdict without its corpus is a configuration, not a
     statement.

  A conforming reader MUST NOT generalize either closed-world rule (e.g. "a dangling link is rejected")
  to the open substrate; outside a sealed scope or a gate, an unresolved reference is *incomplete*, not
  invalid.
- **Qualification is monotone, and is NOT a third closed world.** Environment/tool qualification (Clause
  10) asks for completeness over a spectrum's member set, which may appear closed-world, but is not: the
  member set is fixed by the spectrum's own **content hash** (a *defined* set that travels with the
  spectrum, not one *discovered* per source), and each member check is a **positive existence** (a
  fulfilling foton is resolvable). Adding a source can therefore only *complete* a qualification, never
  revoke one - a not-yet-fulfilled spectrum is **incomplete**, not **failed**. Qualification thus obeys
  monotonicity; a conforming implementation MUST NOT evaluate it with a non-monotone test (e.g. a
  negative existential over "unfulfilled members") that a later source could flip. The signed
  `qualifies-as` acceptance built on top SHOULD cite the fulfilment record (the spectrum-check foton, by
  hash) so the tally is re-derivable rather than asserted.

## 12 Federation and aggregation

Records are immutable and content-addressed, so replication is a conflict-free set union.

- `sync?since=T` returns append-only records since cursor `T`; **mirroring** = `sync` + persistence.
  Because a batch may deliver a scoped child before its seed, ingest MUST settle scoped claims in
  dependency order and skip records that never become valid, always advancing the peer cursor so one
  malformed or hostile record cannot wedge replication. A local-directory overlay (`mirror <dir>`) is
  cursorless overlay-by-hash, so it **re-attempts** a previously-unresolved record whenever a later
  mirror supplies its missing ancestry - an incomplete chain heals as its dependencies arrive.
- **Aggregator independence (Scenario 8).** An aggregator is a **discovery index**: it indexes and
  unions records to help find them. It is **not a store and not a trust anchor**. A conforming
  aggregator MUST NOT be required for verification: every record it surfaces remains independently
  verifiable by hash and signature from the participant that holds it. An aggregator that omits, adds,
  or misreports an entry cannot make an invalid record valid or a valid record invalid; a missing entry
  is a discovery gap, not a trust failure.
- **Byte pinning is OPTIONAL** and lives outside the kernel: a mirror MAY fetch a referenced file's
  bytes, verify against the hash (5.6), and re-serve them. Fetched bytes MUST be rejected if their hash
  differs from the request.
- **Minimum federation surface.** A federating implementation MUST offer these QUERIES, and the
  answers MUST be in the wire form below. **How they are carried is not specified** - a transport is
  an implementation choice (§1), and this clause is about what is asked and what comes back:

  | query | answers |
  |---|---|
  | `producer(hash)` | the foton(s) whose OUTPUT is `hash` |
  | `uses(hash)` | the foton(s) whose INPUT is `hash` |
  | `sync(since)` | records with a local sequence above `since`, in append order, with the new cursor |
  | `blob(hash)` *(optional)* | the pinned bytes for `hash`, if this participant holds them |
  | `claims(subject\|object\|signer\|predicate)` | the claims matching that axis |
  | `claim(id)` | the one claim with that id, or a distinct not-held answer |

  A `claim(id)` for a record the participant does not hold MUST be distinguishable from a record it
  holds with nothing to say - "we do not have it" and "we have nothing about it" are different
  answers, and a reader acts differently on each. An unrecognised or absent query parameter MUST be
  an error, never an empty result: an empty answer to a malformed question is a successful wrong
  answer.

  **Wire form.** `sync` answers `{ "records": [ { "seq", "fotonId"|"claimId", "envelope" } ... ],
  "max": <cursor> }`; the record queries answer `{ "records": [ <envelope> ... ] }`. Envelopes are
  as in §8. Conformance fixtures for these answers live in `../reference/testdata/federation/`.

  *An HTTP(S) binding - `GET /sync?since=`, `GET /claim?id=` and so on - is one realization and is
  described in Annex C. It is informative: an implementation carrying these queries over anything
  else is equally conforming. The reference implementation answers `sync(since)` over **stdout**
  (`plankton records --json --since N`, `nekton records --json --since N`), which is why the fixtures
  are generated from that command rather than written by hand.*

## 13 Long-term verifiability  *(0.1 - subject to change)*

For a record to remain verifiable long after signing, it should carry what durable verification needs.
When a short-lived signing certificate is used (e.g. Sigstore-Fulcio), the transparency-log inclusion
proof (e.g. Rekor) SHOULD be carried **inside the record**, so that verification a year later does not
depend on the certificate still being valid or an external service still answering. The on-record encoding is
§8.1: an inclusion proof is verification material with `scheme: "rekor-entry"`, bound to the record by
its content address like any other. *(Scenario 3. The reference `kton anchor` currently verifies the
proof and prints it to stdout without storing it, and there is no offline re-verification of a saved
proof; both are open.)*

## 14 Publication projections  *(informative)*

A nekton claim MAY be **projected** into an external publication format (e.g. a nanopublication,
RSA-signed with a Trusty URI) for durable, network-discoverable publication. Such a projection is
"the same but different": the projection's content hash (a Trusty-URI hash over normalized RDF)
legitimately differs from the claim's multihash id, **by design**. The binding between the two MUST be
an **explicit provenance reference** (the projection carries a back-reference to the source claim id),
NOT an assumption of hash equality. The way back from a projection to the authoritative claim is via
that reference. In the reference implementation, `nekton export --nanopub` renders this projection with
a *pre-Trusty* namespace (the source claim id stands in for the not-yet-minted Trusty URI); computing
the real Trusty-URI hash and RSA-signing per the nanopublication convention are external-toolchain
steps (§1, out of scope). The source binding is always the explicit `prov:wasDerivedFrom` reference.
*(Scenario 10.)*

## 15 Conformance

A conforming implementation MUST:

1. compute SHA-256 file hashes and canonical JSON (Clause 5) that reproduce the frozen conformance
   vectors in `../reference/testdata/`;
2. for the shipped foton vector, reproduce exactly
   `foton id = sha256:5da55d7885d87097e5decf17d7edf6e49597a655f401249cca66bd77a17121f1` and
   `action_key = sha256:8bcde68d3d76cd4bf158c015c64aa587fb747402ce63dbdb528871488eb897fd`;
3. via `verify` against the published public keys, verify the shipped vectors' DSSE signatures, reject a
   one-byte-tampered payload, and distinguish wrong-key from tampered (§8) - this is a `verify`-time
   guarantee: **ingest** rejects *unsigned* claims (§7.2) but does not verify signatures;
4. index and resolve records per Clauses 11–12, including the completeness/validity distinction (11);
5. enforce the scope/seed/chain grammar (7.4) and reject unsigned claims (7.2) and forged `genesis`
   (7.4);
6. refuse partial spectrum fulfilment (10) and ill-formed reproduction claims lacking a level (9);
7. if it carries verification material (8.1) - which is OPTIONAL to produce and OPTIONAL to carry -
   not reject an unrecognised `scheme`, not treat its absence or invalidity as affecting a record's
   validity or resolvability, and not report a record as verified on the strength of material it did
   not itself evaluate.

The conformance vectors are frozen with deterministic test keys and regenerated by
`../reference/testdata/gen`; CI fails on drift. Additional behavioral scenarios (canonicalization
equivalence, tamper-evidence, cross-repo chains, aggregator independence, missing-link robustness,
publication round-trip) are maintained as the conformance scenario suite.

## 16 Versioning and stability

- Predicate types are versioned in their URI (`/v0`, `/v1`, …) - the breaking-change **contract**
  marker (it moves only on a breaking change, so all of `0.x` is `/v0`).
- A foton's predicate MAY additionally carry **`specVersion`** - the exact spec revision it was authored
  under (e.g. `"0.1"`) - as a **CARRIED, non-covered** field: it is signed and attested but excluded
  from the foton id and action key (which project only inputs/outputs/protocol), so stamping it changes
  no identity. This gives per-record traceability to the exact revision while the spec is pre-1.0.
  A **claim** carries no equivalent: a claim id is the hash of its whole statement, so it has no carried
  region - claims are versioned by their `claim/v0` predicateType.
- This specification is **0.1 (draft)**: shapes MAY change before 1.0. The stable invariants are:
  records are content-addressed and DSSE-signed; identity excludes carried (non-covered) fields;
  plankton records results and nekton records attestations; nekton references plankton by hash only
  (never the reverse); the kernel documents and never executes; and trust is a consumer policy over
  keys, not a property of the kernel.

## Annex A *(informative)* - reuse of established standards

Structure/envelope: in-toto Attestation + DSSE. Hashing/addressing: SHA-256 + multihash. Lineage/agent:
W3C **PROV-O**. General review provenance: **PAV** (`pav:reviewedBy`). Location/retrieval (the
`located-at` mechanism, Clause 12): **DCAT** (`dcat:downloadURL`). Equivalence/hierarchy: **OWL/SKOS**.
Licensing identifiers: SPDX. Publication: nanopublication / Trusty URI (Clause 14). Domain vocabularies
used by *examples* (not the protocol) - EDAM/SWO/STATO/OBI, Cell Ontology, HGNC, SEPIO/micropublication
for evidence - are application vocabulary, not normative kton terms. The full reuse ↔ native mapping and
the reserved `gxp:*` set are in [`vocabulary.md`](vocabulary.md).

## Annex C *(informative)* - an HTTP binding for Clause 12

One realization of the §12 queries, and the one the reference client speaks. Nothing here is
normative: an implementation carrying the same queries and the same wire form over another transport
conforms equally.

```
GET /producer?hash=<content hash>          -> { "records": [ <envelope> ... ] }
GET /uses?hash=<content hash>              -> { "records": [ <envelope> ... ] }
GET /sync?since=<cursor>                   -> { "records": [ ... ], "max": <cursor> }
GET /blob?hash=<content hash>              -> the bytes, or 404; 400 if not a content hash
GET /claims?subject=|object=|signer=|predicate=  -> { "records": [ <envelope> ... ] }
GET /claim?id=<claim id>                   -> { "records": [ <envelope> ] }, or 404 if not held
GET /material?subject=<record id>          -> { "subject", "material": [ ... ] }   (§8.1)
```

A malformed or missing parameter answers 400. A record this participant does not hold answers 404.
Both are distinct from an empty `records` list, which means "held, nothing matches".

The reference implementation ships the **client** for this binding (`kton mirror`) and no server: a
specification of a protocol is not a place to distribute a network service, and a server that binds
a port has security obligations - authentication, transport security, rate limiting, request bounds -
that belong to a deployment rather than to a reference. Writing one over the table above is a small
amount of code in any language, and `../reference/testdata/federation/` fixes the bytes it must
produce.

It does answer §12 over a different binding: `plankton records --json --since N` and
`nekton records --json --since N` return exactly the `sync(since)` document above on stdout. A server
over HTTP is then a shell around that, which is what "the transport is not specified" means in
practice.

## Annex B *(informative)* - scenario → clause map

1 Canonicalization → 5. 2 Tamper → 5.6, 8. 3 Long-term → 13. 4 Identity → 8. 5 Cross-repo chain → 7.4,
11. 6 Normalization level → 9. 7 Spectrum fulfilment → 10. 8 Aggregator independence → 12. 9 Missing
links → 11. 10 Publication round-trip → 14.
