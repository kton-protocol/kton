# Templates & aliases - annotating for QM

How nekton stays minimal while supporting real QM annotation. Three tiers, by complexity, none
of which add anything to the kernel: the kernel still stores opaque `TermRef`s and signed claims.

> **The example templates and alias vocabulary are not part of the protocol** - they are federated
> example data and live in a curated companion repo, **[`gitmick/kton-examples`](https://github.com/gitmick/kton-examples)**.
> This document describes the template/alias *mechanism* (the `kton.dev/template/v0` and
> `kton.dev/aliases/v0` schemas); the concrete `*.json` referenced below are illustrations from that repo.

## The three tiers

| tier | for | mechanism | surface |
|------|-----|-----------|---------|
| **alias** | one predicate, one value | short name → IRI, resolved *before* signing | `--predicate derived` |
| **template** | several fields that belong together | named predicate + typed fields | `--set k=v` (CLI) or a form (UI) |
| **template + file / UI** | a value that is *bytes*, or needs human judgement | `file`-typed field → content hash; `widget` hints render a form | hashed ref / cockpit form |

The rule is just arity and value-kind: one IRI + one scalar → **alias**; multiple scalars that
go together → **template**; a value that is a document, or a field a person must fill carefully →
**file field / UI**.

## Aliases (`aliases/aliases.json`)

Pure sugar. An alias resolves to a canonical IRI **before** the claim is built, so the signed
wire form always carries the full IRI - the alias never enters the signed bytes.

```
prefixes:  prov → http://www.w3.org/ns/prov#   gxp → https://kton.dev/v/gxp/   ctx → …/ctx/   …
terms:     derived → prov:wasDerivedFrom        reviewed → gxp:reviewed            …
```

Resolution: a value with `://` is already an IRI; a bare term resolves via `terms`; a `prefix:local`
CURIE expands via `prefixes`. So `reviewed → gxp:reviewed → https://kton.dev/v/gxp/reviewed`.

Aliases **federate** like everything else: the file is content-addressed, and any binding is
equivalently a signed `owl:sameAs` claim, so a consumer can adopt, extend, or remap your alias set
over the union of registries it sees. nekton mandates none of it.

## Templates (`templates/*.json`) - schema v0

A template is content-addressed JSON declaring a predicate, optional context, and typed fields.
It is shapes over opaque IRIs; it produces one signed claim.

```json
{
  "schema": "https://kton.dev/template/v0",
  "name": "gxp/review",
  "target": "foton",                 // file | foton | either  (what the subject is)
  "predicate": "reviewed",           // IRI or alias
  "context": "ctx:gxp",              // IRI or alias (optional)
  "vocab": "sha256:…",              // optional, federated term definitions
  "fields": {
    "outcome": {"type":"enum","values":["pass","fail"],"required":true,"role":"object","widget":"enum"},
    "sop":     {"type":"string","required":true,"role":"object","widget":"text"},
    "report":  {"type":"file","mediaType":"application/pdf","required":true,"role":"evidence","widget":"file"},
    "notes":   {"type":"string","required":false,"role":"object","widget":"textarea"}
  }
}
```

Field grammar:
- **type** - `string | enum | date | ref | file`.
- **role** - `object` (scalar/ref goes into the claim's `object{}`) or `evidence` (a ref goes into
  `evidence[]`). Default: scalars → `object`, files → `evidence`.
- **file** - the value is a **path**; nekton hashes it to a `{hash, mediaType}` ref. The bytes are
  *not* stored - only the content hash, exactly like a plankton file ref. This is how "files" enter
  QM records: a signed PDF protocol, a validation report, a diagram - referenced by hash, living
  wherever they already live.
- **widget** - advisory rendering hint (`text | textarea | enum | date | ref | file`) a UI may read
  and the CLI ignores. The kernel never reads it; it is metadata like `vocab`.

## File fields = content references (not bytes)

A `file` field does not embed a document. It hashes it and stores a ref:

```
"evidence": [ { "hash": "sha256:2cccd399…", "mediaType": "application/pdf" } ]
```

So a QM review *points at* its evidence PDF by hash. The PDF can be registered in plankton as a
file ref `{hash, uri}` and pinned or not - availability is a separate, optional concern. The claim
remains small, signed, and federated; the heavy bytes stay external. (This is the same discipline
as plankton's "no filestore".)

## UI is a cockpit concern (template-as-data)

For fields a human must fill thoughtfully - a structured risk assessment, a multi-field review -
a **UI renders the template as a form**: each field's `widget` becomes an input, the person fills
it, the cockpit emits the resulting signed claim. Crucially:

- The **template declares** the fields; the **cockpit renders** them. nekton never grows a form
  engine - it stores the template (content-addressed, federated) and records the produced claim.
- **Template-as-data, not template-as-code:** the form definition travels by hash, so one template
  drives many UIs (CLI `--set`, a web form, a workbench) identically. The cockpit stays a lens; the
  meaning and shape federate. (A cockpit *may* ship richer code for a template name, but then that
  form no longer federates - a deliberate trade, not the default.)

## Worked QM example (verified)

A GxP review of the tally foton, evidence = a hashed PDF, signed:

```console
$ nekton-annotate --foton tally.foton.dsse.json \
    --template gxp/review --templates-dir ./templates --aliases ./aliases/aliases.json \
    --set outcome=pass --set sop=SOP-QM-014 --set report=review.pdf \
    --set notes="Reviewed vote outcome and lineage; reproducible at L1." \
    --by "CN=A. Reviewer, QM" --sign reviewer.pem -o claim.review.dsse.json
```

Produces a `review` claim (envelope elided):

```json
"predicate": {
  "by": "CN=A. Reviewer, QM",
  "context": { "uri": "https://kton.dev/ctx/gxp" },
  "evidence": [ { "hash": "sha256:2cccd399…", "mediaType": "application/pdf" } ],
  "object":   { "notes": "…", "outcome": "pass", "sop": "SOP-QM-014" },
  "predicate":{ "uri": "https://kton.dev/v/gxp/reviewed" },
  "when": "2026-06-30T18:25:22Z"
}
```

Verified: alias `reviewed` → full IRI; `ctx:gxp` → full IRI; the `report` file hashed into
`evidence` (hash == the PDF); Ed25519/DSSE signature valid; payload is canonical JSON. Tooling:
`bash + sha256sum + base64 + openssl + jq` (jq only to read the template/alias JSON) - no Python.

## QM mapping (PROV-O + GxP, all by reference)

| QM act | template / alias | predicate IRI |
|--------|------------------|---------------|
| reviewed (four-eyes) | `gxp/review` | `…/v/gxp/reviewed` |
| tool validation performed | `gxp/tool-validation` | `…/v/gxp/validation-performed` |
| environment qualified | (alias `envQualified`) | `…/v/gxp/env-qualified` |
| risk accepted | `risk/accept` | `…/v/gxp/risk-accepted` |
| derivation / lineage | `prov/derived-from` | `prov#wasDerivedFrom` |
| generated-by / used | (alias `generatedBy`/`used`) | `prov#wasGeneratedBy` / `prov#used` |
| responsibility | (alias `onBehalfOf`) | `prov#actedOnBehalfOf` |

PROV-O is one vocabulary among these - referenced, never imported. A reasoner that wants to read
your `pmx`/`gxp` terms *as* PROV does so via signed `sameAs` mapping claims, downstream.

## What is deliberately NOT here

- No ontology engine, no reasoner, no form engine in the kernel.
- `widget`/`vocab` are advisory; the kernel never interprets them.
- File **bytes** are never stored - only hashes. Availability/pinning is external & optional.
- Whose signatures count (which reviewer, which qualifier) is **trust policy** - a cockpit/galaxy
  decision, not the kernel's.
