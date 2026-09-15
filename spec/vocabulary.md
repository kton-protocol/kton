# kton vocabulary - reuse and native terms

*Informative annex to [`SPEC.md`](SPEC.md). Vocabulary policy per [decisions](../docs/decisions.md) §20: reuse a published
ontology wherever one fits; mint a kton-native IRI only for a concept no standard covers; keep the
regulated terms reserved. The **protocol** defines a small owned set; specific **predicates** used by
examples are application vocabulary, not the protocol.*

## 1. Reused published ontologies (do not reinvent)

| Concept | Standard | Term(s) |
|---|---|---|
| Statement / envelope | in-toto Attestation + DSSE | the wire form (Clause 6.6 / 7.3 / 8) |
| Content hash / addressing | multihash | `sha256:` |
| Lineage, agents, activities | **PROV-O** | `prov:wasDerivedFrom`, `prov:used`, `prov:wasGeneratedBy`, `prov:wasAttributedTo`, `prov:wasAssociatedWith`, `prov:actedOnBehalfOf` |
| Authoring / versioning provenance | **PAV** | `pav:createdBy`, `pav:authoredBy`, `pav:retrievedFrom`. PAV has **no** review property; see §3 |
| Key -> principal control (identity) | **W3C Security Vocabulary** | `sec:controller`, `sec:Multikey` - a signed key-to-principal binding is a lightweight Verifiable Credential; keys are named by their content IRI (`pk:<hash>`), principals by IRI (`did:web:`, `model:`) |
| Location / retrieval | **DCAT** | `dcat:downloadURL` (the `located-at` mechanism; Clause 12) |
| Equivalence / hierarchy | **OWL / SKOS** | `owl:sameAs`, `skos:broader` |
| Licensing identifiers | SPDX | license ids |
| Publication projection | nanopublication / Trusty URI | Clause 14 |
| Evidence / assertion modelling | **SEPIO** / micropublication | evidence graphs over review claims *(candidate; not yet mapped to specific terms)* |

## 2. kton-native terms (owned - no published equivalent)

Defined under `kton.dev` (IRIs to be served; `w3id.org/kton` is a candidate stable home). Each is small
and versioned:

| Term | IRI | Meaning |
|---|---|---|
| foton | `https://kton.dev/foton/v0` | a reproducible result: inputs → protocol → outputs (Clause 6) |
| claim | `https://kton.dev/claim/v0` | a signed subject–predicate–object attestation (Clause 7) |
| scope / seed | `https://kton.dev/scope/v0` | the structural chain grammar (Clause 7.4) |
| reproduces (L0/L1/L2) | `nk:reproduces`, `level_reached` | reproduction identity level (Clause 9) |
| spectrum / fulfilment | (spectrum object) | a tool/environment definition + its fulfilment (Clause 10) |
| qualifies-as | `nk:qualifies-as` | binds a concrete env/tool to an env/tool spectrum (Clause 6.5/10) |
| env-spectrum | (a `SpectrumId`) | an environment qualification class (Clause 6.5) |
| action_key | (computed) | the identity of a computation, inputs+protocol (Clause 6.3) |
| confirmed | `nk:confirmed` | a lightweight general confirmation (no regulatory weight) |

## 3. Application / example vocabulary (NOT the protocol)

These demonstrate the protocol; the kernel treats every predicate as an opaque IRI (Clause 7.1) and
never requires them. They live in aliases/templates, not the spec.

- **Governance example:** `vote`, `vote-initialised`, `delegate` (liquid democracy).
- **Regulated:** a namespace of its own for claims that assert regulated weight - a review performed
  under a validated process, a qualified environment, an accepted risk, a deviation, a CAPA.
  **Use such a term only when a real validated process stands behind the claim.**

  Review uses an application term of its own. No published ontology defines a "reviewed by"
  property, and a passive one would be the wrong shape anyway: its object is the reviewer, where
  the verdict belongs. The object is the verdict; the reviewer is the signature.

  This annex does not name that namespace or enumerate its terms. Application vocabulary lives in
  aliases and templates and moves independently of the specification; an annex that reserved it
  would document a vocabulary no example uses. The live set is whatever
  [`gitmick/kton-examples`](https://github.com/gitmick/kton-examples) ships in `templates/` and
  `aliases`, and the kernel requires none of it (Clause 7.1).
- **Domain example:** `pmx:model-role` (pharmacometrics); `ddmore-entry`, `workbench-run` (integrations).

## 4. Deprecated

- **`identity-equivalent`** → removed. Byte/canonical identity is `reproduces` at `level_reached: L0`/`L1`
  (Clause 9); logical identity is `owl:sameAs`. There is no separate native term.
- **`nk:actsAs`** → alias of **`sec:controller`** (W3C Security Vocabulary). Key-to-principal control
  reuses the published DID / Verifiable-Credential vocabulary; `actsAs` is kept only as an alias
  resolving to `sec:controller`. See [decisions](../docs/decisions.md) §21.
