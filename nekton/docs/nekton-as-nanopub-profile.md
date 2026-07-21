# nekton as a nanopublication profile - worked examples

Reuse-don't-reinvent, made concrete. A nekton statement **is** a nanopublication; the seedchain is a
`prev`/genesis link carried *inside* nanopublications; the tally stays a plankton foton. Below: the
same `gxp/review` and a `vote` from our tooling, rendered as real nanopublication RDF (TriG), plus
the seed genesis and the chain link.

> Encoding note: RDF/TriG is the **interop face**, not a kernel mandate. A nekton claim *renders as*
> a nanopublication for network reuse; the inert core still stores opaque IRIs + hashes.
>
> Implemented: **`nekton export --nanopub <claim.dsse.json>`** renders any signed claim (and a seed)
> to the four-graph TriG below - subject-by-hash → `pk:<hash>`, the multi-field object bag → a
> blank node with each field key resolved to an IRI via the vocab/aliases, `by`/`when`/`context` →
> provenance, and the `scope`/`prev`/`genesis` seedchain → pubinfo.
>
> **The signature seam (RSA vs Sigstore) is handled honestly, not faked.** A nanopublication is
> conventionally signed with **RSA over the normalized RDF** (`npx:hasSignature`); our claim is signed
> with **Ed25519/DSSE over the in-toto Statement bytes** (Sigstore-aligned - that is what buys us
> Rekor/Fulcio + in-toto/SLSA). The two do not interchange: the DSSE bytes are not the RDF bytes, and
> Ed25519 is not the npx-conventional RSA. So the renderer does **not** emit `npx:hasSignature`; it
> carries the DSSE attestation as nekton provenance (`nk:signedAs "in-toto/DSSE"`, `nk:keyid`,
> `nk:dsseSignature`) and lets **content-addressing** (the trusty-URI = claim id) carry integrity. A
> nekton-aware consumer verifies via `nekton verify`; a Rekor anchor (`kton anchor`) is our
> network-trust witness, the Sigstore-world parallel to the nanopub network. To emit a
> **network-verifiable** nanopublication one must **re-sign over the canonical RDF (RSA) at this export
> edge** - that step is deliberately deferred (needs an RDF canonicalizer + RSA).

## Anatomy recap

A nanopublication is four named graphs: a **Head** declaring the other three, an **assertion** (the
content), its **provenance** (who/when/how), and **publication info** (metadata about the nanopub
itself, incl. signature). Identified by a Trusty URI whose tail is a content hash of the RDF.

## Mapping: nekton claim → nanopublication

| nekton claim field | nanopublication home | term |
|---|---|---|
| `subject` (a foton/ray/file hash) | assertion - subject of the triple | a content-addressed IRI (`pk:<hash>`) |
| `predicate` (opaque IRI/alias) | assertion - predicate | the resolved IRI (`gxp:reviewed`, `nk:vote`) |
| `object` (scalars: outcome, sop…) | assertion - object / a small resource | your terms (`gxp:outcome`, …) |
| `evidence` (hashed PDF) | assertion or provenance - by hash | `gxp:evidence pk:<hash>` + `dct:format` |
| `by` | provenance + pubinfo | `prov:wasAttributedTo`, `pav:createdBy` |
| `when` | provenance + pubinfo | `prov:generatedAtTime`, `dct:created` |
| `context` | provenance | `dct:subject ctx:<…>` |
| signature (DSSE) | pubinfo | `npx:hasSignature` (see signing seam) |
| **`scope` / `prev` / `genesis`** (seedchain) | **pubinfo** | **`nk:scope`, `nk:prev`, `nk:genesis`** ← your delta |

Shared prefixes for all examples:
```turtle
@prefix np:   <http://www.nanopub.org/nschema#> .
@prefix npx:  <http://purl.org/nanopub/x/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix pav:  <http://purl.org/pav/> .
@prefix dct:  <http://purl.org/dc/terms/> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix orcid:<https://orcid.org/> .
@prefix nk:   <https://kton.dev/v/> .
@prefix gxp:  <https://kton.dev/v/gxp/> .
@prefix ctx:  <https://kton.dev/ctx/> .
@prefix pk:   <https://kton.dev/o/> .            # content-addressed plankton objects: pk:<sha256>
@prefix scope:<https://qm.acme.example/scope/> .
```

## Example A - `gxp/review` as a nanopublication

The exact claim our `nekton-annotate` produced (review of a foton, evidence = a hashed PDF):

```trig
@prefix this: <https://qm.acme.example/np/rev-7c1d.> .   # Trusty URI; tail = content hash
@prefix sub:  <https://qm.acme.example/np/rev-7c1d.#> .

sub:Head {
  this: a np:Nanopublication ;
    np:hasAssertion       sub:assertion ;
    np:hasProvenance      sub:provenance ;
    np:hasPublicationInfo sub:pubinfo .
}

sub:assertion {
  pk:048755ecd7 gxp:reviewed sub:review .        # subject = the foton (an execution), by hash
  sub:review
    gxp:outcome  "pass" ;
    gxp:sop      "SOP-QM-014" ;
    gxp:evidence pk:2cccd399 ;                    # the review PDF, by content hash (bytes external)
    dct:description "Reviewed vote outcome and lineage; reproducible at L1." .
}

sub:provenance {
  sub:assertion
    prov:wasAttributedTo orcid:0000-0002-1825-0097 ;
    prov:generatedAtTime "2026-06-30T18:25:22Z"^^xsd:dateTime ;
    dct:subject          ctx:gxp .                # the context IRI
  pk:2cccd399 dct:format "application/pdf" .
}

sub:pubinfo {
  this:
    pav:createdBy orcid:0000-0002-1825-0097 ;
    dct:created   "2026-06-30T18:25:22Z"^^xsd:dateTime ;
    nk:scope      scope:muni-5101 ;               # ← seedchain: which scope (seed trusty URI)
    nk:prev       <https://qm.acme.example/np/rev-3f0a.> .  # ← previous nanopub in this chain
  sub:sig
    npx:hasSignatureTarget this: ;
    npx:hasAlgorithm  "ED25519" ;
    npx:hasPublicKey  "MCowBQYDK2Vw…" ;
    npx:hasSignature  "GxSXEKVtLiHs…==" .
}
```

Everything from our DSSE claim is here: subject-by-hash, the `outcome`/`sop` object fields, the PDF
in `evidence` by hash, `by`/`when`/`context`, and the **`nk:scope` + `nk:prev`** seedchain link.

## Example B - a `vote` as a nanopublication

```trig
@prefix this: <https://qm.acme.example/np/vote-a1f0.> .
@prefix sub:  <https://qm.acme.example/np/vote-a1f0.#> .

sub:Head {
  this: a np:Nanopublication ;
    np:hasAssertion sub:assertion ; np:hasProvenance sub:provenance ;
    np:hasPublicationInfo sub:pubinfo .
}

sub:assertion {
  orcid:0000-0001-2345-6789 nk:vote sub:ballot .          # alice votes
  sub:ballot nk:motion <https://qm.acme.example/motions/popPK-v3> ;
             nk:choice "approve" .
}

sub:provenance {
  sub:assertion
    prov:wasAttributedTo orcid:0000-0001-2345-6789 ;
    prov:generatedAtTime "2026-06-30T09:00:00Z"^^xsd:dateTime ;
    dct:subject          ctx:popPK-approval .
}

sub:pubinfo {
  this: pav:createdBy orcid:0000-0001-2345-6789 ;
    dct:created "2026-06-30T09:00:00Z"^^xsd:dateTime ;
    nk:scope scope:muni-5101 ;
    nk:prev  <https://qm.acme.example/np/vote-9c20.> .
  sub:sig npx:hasSignatureTarget this: ;
    npx:hasAlgorithm "ED25519" ; npx:hasPublicKey "MCowBQYDK2Vw…" ;
    npx:hasSignature "iJZ2q0…==" .
}
```

A delegation is the same shape with `nk:delegate` and an object identity. Reviews, votes,
delegations, risk sign-offs - all just assertions with different predicates, which is exactly what a
nanopublication was always able to carry.

## The seedchain, in nanopublications

### The genesis (seed) nanopublication - its Trusty URI **is** the `scope_id`

```trig
@prefix this: <https://qm.acme.example/np/seed-muni5101.> .
@prefix sub:  <https://qm.acme.example/np/seed-muni5101.#> .

sub:Head {
  this: a np:Nanopublication ;
    np:hasAssertion sub:assertion ; np:hasProvenance sub:provenance ;
    np:hasPublicationInfo sub:pubinfo .
}

sub:assertion {
  scope:muni-5101 a nk:Scope ;
    dct:title      "Municipality 5101 - popPK v3 ballot" ;
    nk:responsible orcid:0000-0001-aaaa , orcid:0000-0002-bbbb , orcid:0000-0003-cccc .
}

sub:provenance {
  sub:assertion
    prov:wasAttributedTo scope:county-51 ;               # the county anchors the scope
    prov:generatedAtTime "2026-06-30T07:00:00Z"^^xsd:dateTime .
}

sub:pubinfo {
  this: nk:genesis true ;                                # NO nk:prev - this opens the chain
    nk:scope scope:muni-5101 ;                           # self
    pav:createdBy orcid:0000-0001-aaaa .
  sub:sig npx:hasSignatureTarget this: ; npx:hasAlgorithm "ED25519" ;
    npx:hasPublicKey "…" ; npx:hasSignature "…" .
}
```

- **`scope_id` = this nanopublication's Trusty URI** (its content hash). Unforgeable, self-certifying.
- **The county "connects" the municipality by holding this one Trusty URI** - the whole trust
  relationship is that value.
- Every later nanopublication in the scope carries `nk:prev` → the previous one, and `nk:scope` →
  this seed. Remove or reorder any link and the chain breaks (`Seed ← vote ← … ← count-finished`).

### The seal - `count-finished` (still a nanopublication)

```trig
sub:assertion {
  scope:muni-5101 nk:count-finished sub:result .
  sub:result gxp:tally [ nk:choice "approve" ; nk:count 512 ] ,
                       [ nk:choice "reject"  ; nk:count 488 ] ;
             nk:turnout 1000 ;
             gxp:protocol pk:9f3c…  .                    # signed count-board tally sheet, by hash
}
sub:provenance { sub:assertion prov:wasAttributedTo orcid:0000-0001-aaaa ,
                   orcid:0000-0002-bbbb , orcid:0000-0003-cccc .   # ALL responsible signed
                 sub:assertion prov:generatedAtTime "…"^^xsd:dateTime . }
sub:pubinfo { this: nk:scope scope:muni-5101 ; nk:prev <…last-vote…> ; nk:closesChain true .
              sub:sig … }
```

## What stays a plankton foton (the boundary that reuse *sharpens*)

The **votes** are nanopublications. The **count** is not - it is a reproducible computation, so it
stays a plankton `kind=tally` foton (in-toto/DSSE), exactly as built. Nanopublications give you the
attributed-statement half; they do **not** and should not become a re-runnable execution. A
`confirmed` nanopublication then points at the tally foton by hash:

```trig
sub:assertion { pk:138876cc nk:confirmed sub:ratify .   # subject = the tally FOTON (plankton), by hash
                sub:ratify dct:description "County result ratified." . }
```

So adopting nanopublications for nekton **sharpens** the plankton/nekton line: a count isn't an
assertion, it's a reproducible result that assertions point at.

## The one real seam: two signing conventions

- Nanopublications sign natively: `npx:hasSignature` over a normalized RDF form, tied to the Trusty
  URI. plankton fotons sign via **in-toto/DSSE** over statement bytes.
- **Recommendation (cleanest reuse, per layer):** nekton statements → **nanopublication-native
  signing** (you get the network, Nanobench, trusty-URI addressing); plankton fotons → **in-toto/DSSE**
  (you get SLSA/Sigstore tooling). Two conventions, one per layer, each idiomatic to its ecosystem -
  rather than forcing DSSE onto RDF or RDF onto fotons.
- If you need a single internal convention, keep DSSE internally and **re-sign at the nanopublication
  edge on export**. Either way, decide this deliberately - it is the only place the reuse isn't free.

## What remains genuinely yours to build

Almost nothing in the statement layer - and that's the win:

- **Not** a claim format (nanopublications), **not** an envelope (in-toto/DSSE/Sigstore), **not**
  content-addressing (Trusty URIs), **not** argument/evidence vocabulary (micropublications).
- **Yours:** the `nk:scope` / `nk:prev` / `nk:genesis` **seedchain profile** on top of nanopublications
  (two link terms + the genesis rule), the **reproducible aggregator gate** (`kind=aggregate` foton
  enforcing chain-from-seed ∧ all-responsible-signed ∧ registered), and the **plankton reproducible
  half** with L0/L1/L2 identity. That is a small, sharp surface - which is exactly what
  reuse-don't-reinvent is supposed to leave you holding.
```
