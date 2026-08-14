# Decisions and rationale

The design decisions the code and the spec rest on, with the *why* - so a reader who finds a
constraint in the source can look up what it is protecting instead of guessing, and so a contributor
knows which lines are load-bearing before removing one.

Status tags: **[settled]**, **[leaning]**, **[open]**.

**On the numbering.** Sections are cited by number from code comments, `go.work`, `spec/vocabulary.md`
and the CI guard. The numbers are therefore **stable identifiers, not an ordering** - a gap means a
section of the working record is not part of the public rationale (it concerns positioning, planning
or unreleased work), never that a decision was withdrawn. Numbers are never reused.

---

## 1. The two primitives

**[settled]** All data processing decomposes into exactly two things:

- **plankton** = *reproducible results* - a deterministic function of pinned inputs
  (`inputs → protocol(+environment) → outputs`), verified by re-execution or by hash.
- **nekton** = *attestable commitments* - signed, attributed statements *about* those results, about
  files, and about other statements.

**The dividing invariant:** can a machine **verify** it (re-run, hash) → plankton. Can it only be
**vouched for** by a person → nekton. This is a falsifiable test, and it is what keeps plankton small.

**Rationale.** nekton was extracted from plankton because attestations bloated the lineage substrate,
and because they are not reproducible facts: they are signed commitments. They belong in their own
layer.

## 2. Dependency direction and shared primitives

**[settled]** `nekton → plankton`, never the reverse. A nekton claim's subject is a plankton hash;
plankton knows nothing of nekton. Both share the same primitives: content addressing (SHA-256),
DSSE signatures, federation by hash. One system, two layers.

The same pattern holds one level up: a cockpit depends on the kernels, and nothing depends on the
cockpit. `kton` in this repo is that cockpit.

**Enforced, not merely intended:** `scripts/check-import-direction.sh` runs in CI and fails the build
on a violating import. The same guard carries the WASM-cleanliness rule (no `net/http` in a kernel)
and the never-executes rule from §3 (no `os/exec` anywhere).

## 3. plankton is never an executor

**[settled, load-bearing]** plankton's *entire* interface is: **a signed Statement arrives → record
it.** It never runs, sandboxes, re-runs, fetches, normalizes, compares, or reasons.

- All *running* lives in **executors** - separate tools, registered by `kind`, that emit fotons.
- The forbidden verbs: there is no `plankton run`, no `plankton rerun`, no `plankton normalize`.
- A qualification re-run is therefore: an executor re-runs → `plankton compare` does pure hash
  equality → a `kind=compare` executor computes L0/L1/L2 and emits a *verdict* Statement →
  `plankton record` ingests it. Acceptance of the verdict is a nekton claim.

**Rationale.** The opaque protocol plus records-only is the wall that stops the substrate from
growing back into the workbench it was extracted from. A substrate that can run things acquires
opinions about how things are run, and then it is no longer a substrate.

## 4. nekton is minimal, ontology-agnostic, and federated

**[settled]** The nekton kernel has one type: the signed `Claim`
(`subject, predicate, object?, context?, by, when, why?, evidence?`). `predicate` and `context` are
**opaque `TermRef`s** - nekton carries any vocabulary and **mandates none**. Meaning and equivalence
resolve **downstream**, over the federated union of registries; a `sameAs` mapping is itself a signed
claim. No ontology engine and no reasoner in the kernel.

Anyone can say anything, signed. Disagreement is two claims, both kept.

## 5. Reproduction-identity cut

**[settled]** The line between the layers runs *through* reproduction-identity:

- the **mechanical** equivalence check (L0 byte, L1 canonical, L2 within a declared tolerance -
  all recomputable) → **plankton**, as a `kind=compare` executor whose verdict plankton records;
- the **signed acceptance** of that equivalence ("valid for this purpose") → **nekton**.

Rule of thumb: *the computation* is plankton; *the acceptance of the computation* is nekton.

## 20. Vocabulary and namespace strategy

**[settled]** Reuse *published* ontologies as far as possible; introduce **no** new ontology where a
standard already covers the concept. For the terms that genuinely remain, do not ad-hoc-mint strings:
define a small, versioned vocabulary at a namespace we control, with IRIs that resolve to term
definitions. The namespace is `kton.dev`.

**Reused where a standard exists:**

| concern | vocabulary |
|---|---|
| statement structure | in-toto Attestation (the foton shape) + DSSE (envelope) |
| lineage, derivation, agent, activity | PROV-O (`prov:wasDerivedFrom`, `used`, `wasGeneratedBy`, `Agent`) |
| evidence, support, dispute, supersession | micropublication + SEPIO-style terms |
| review by an actor | PAV (`pav:reviewedBy`) |
| identity / key binding | W3C Security Vocabulary (see §21) |
| file locations | DCAT (`dcat:downloadURL`, `dcat:accessURL`) |
| licensing | SPDX identifiers |
| hashes | multihash / `sha256:` |
| workflow steps, tools, stats | EDAM, SWO, STATO, OBI |

**The load-bearing cut: protocol vocabulary vs. example vocabulary.** The protocol defines the
*structure* plus a few mechanisms. Specific *predicates* are applications layered on top and are
**not part of the protocol**.

- **Protocol (defined and owned):** `foton` (the in-toto predicateType and its shape: inputs /
  `protocol` {kind, ref, descriptor, environment} / outputs), `action_key`, `reproduces` with
  `L0`/`L1`/`L2` and `level_reached`, `spectrum` / `fulfilment` / `qualifies-as` / `env-spectrum`,
  `scope` / `seed`, and the generic nekton **claim** structure (signed subject-predicate-object).
  That is the whole owned vocabulary.
- **Example / application (not protocol):** the voting set (`vote`, `delegate`), any `gxp:*` set,
  review verbs, and integration predicates. These ship as aliases and templates in a companion
  example repo, never as the protocol ontology. The protocol says only "a claim has a predicate IRI";
  *which* predicates exist is open and application-defined.

**Scope/seed stay protocol.** The scope/seed *chain grammar* is a kernel mechanism (`scope/v0`) - the
general "anchor a claim in an accountable chain" primitive that federation and the verify-a-chain-from
-its-seed guarantee rest on. Only the voting *predicates* are examples. See SPEC §7.4.

**Two rules that keep the vocabulary honest:**

- **Prefer dropping a term to renaming it.** `identity-equivalent` was removed rather than migrated:
  it was redundant with `reproduces` at `level_reached: L0`/`L1`, and `owl:sameAs` covers genuine
  logical identity.
- **Terminology must not claim more than the process delivers.** Regulated-review verbs assert a
  *validated regulatory process* and may be used only where one actually stands behind the claim.
  Ordinary review uses general vocabulary (PAV, SEPIO). A regulated set is a *specialization* of
  general review, never the default. This is a correctness rule, not a stylistic one: a term that
  overclaims is a false statement made by the vocabulary rather than by the signer.

## 21. Identity vocabulary - a key binding is a Verifiable Credential

**[settled]** The nekton identity claim - "this key belongs to, or acts for, this principal" - is a
lightweight **Verifiable Credential** expressed in the **W3C Security Vocabulary** (the vocabulary
DIDs and VCs already use), not an ad-hoc form. Three parts:

- **subject (the key)** = its content-addressed IRI `pk:<full sha256(pubkey)>`, in the same
  `https://kton.dev/o/` namespace file and foton hashes use, typed `sec:Multikey`
  (`sec:Ed25519VerificationKey2020` is acceptable). The 16-hex `keyid` is that hash's prefix - a
  display fingerprint, **not** a separate identifier.
- **predicate** = `sec:controller` (`https://w3id.org/security#controller`).
- **object (the principal)** = a real IRI - `did:web:…` for a person, an org URI, a model IRI for a
  model - never a bare string, so it merges in the RDF/nanopublication export by joining at shared
  IRIs.

**Why.** Choosing the DID/VC vocabulary now means the authority-backed tier needs no redo: a Sigstore
Fulcio certificate *already is* exactly a `sec:controller` statement (key → OIDC principal), and SSH
`allowed_signers` or a model CA slot into the same shape. Content-addressed key IRIs keep identity
federating by hash like everything else. Reversible via `owl:sameAs` if a better vocabulary appears.

**A binding is only worth the authority that signed it.** A key-to-principal statement is a claim like
any other: it confers nothing unless it verifies against an authority the *reader* trusts. Counting
distinct keys is not counting distinct people - see `docs/trust.md`.
