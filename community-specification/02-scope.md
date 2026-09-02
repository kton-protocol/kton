# Scope

This Working Group develops **kton**, a specification for **content-addressed data provenance**: a
minimal, transport-neutral format and set of verification semantics for recording *how a result was
produced* and *what has been attested about it*, such that any party can re-derive and independently
verify those records without trusting their producer.

kton has two layers:

- **plankton** - re-derivable, content-addressed **results**. A *foton* records a transformation edge
  (input tree → protocol → output tree), identified by the content hash of its canonical form. The
  identity of a computation (its *action key*) is derived from its inputs and protocol, independent of
  its outputs, so equal computations coincide and reproductions can be compared.
- **nekton** - signed **attestations** about results. A *claim* is a signed subject–predicate–object
  statement over content hashes (and other claims), organized into accountable scope/seed chains.

## In scope

The specification defines, and the patent commitments of contributors and licensees extend to:

1. **On-disk formats** - the foton and claim structures and their fields; the in-toto Statement / DSSE
   envelope wire form.
2. **Canonicalization and content-addressing** - the exact canonical-JSON rules and the multihash /
   `sha256:` addressing by which identity is computed. (Canonicalization is interoperability-critical
   and is specified precisely.)
3. **Verification semantics** - how a party checks a signature, resolves a subject, walks a scope/seed
   chain, and detects tampering.
4. **The signing / attestation model** - that records are signed by keys (agent- or human-held);
   identity is established by key, not by a central authority. Both signature regimes are in scope as
   *models*: ephemeral operational signatures and permanent publication signatures.
5. **The reproduction and normalization model** - reproduction identity levels (byte-identical /
   canonical-identical / within-tolerance) and normalization expressed as a linked, attested foton.
6. **The tool-qualification (Spectrum) model** - defining a tool by its reference fotons and the
   fulfilment check that qualifies a candidate against it.
7. **The aggregation / discovery model** - the semantics by which an aggregator indexes and unions
   records. An aggregator is an **index, not a store and not a trust anchor**: every record it surfaces
   remains independently verifiable by hash and signature.
8. **The attachment point for external verification material** - the shape by which evidence produced
   by another scheme (an identity witness, a time witness) binds to a record by its content address,
   and the boundaries that keep it evidence rather than a precondition. The *evaluation* of any such
   evidence is out of scope (below).

## Out of scope

The following are implementation choices, not part of the specification, and carry no patent
commitment under this Scope:

- **Specific transports and hosting** - git, GitHub, HTTP, object stores, or any particular network
  protocol. kton records are transport-neutral.
- **Specific signing backends** - e.g. Sigstore/keyless, RSA/nanopublication projection, a particular
  transparency log, or an eIDAS trust service. These are concrete realizations of the in-scope signing
  *model*, and **the evaluation of any evidence they produce** - which issuers, trust lists or
  identities count - is likewise out of scope: that is a consumer's trust policy, not a property of a
  record.
- **Document-rendered signature forms** - e.g. signed PDFs (PAdES). These sign a *rendering* of a
  record, whose relationship to the record's canonical bytes is not content-addressed; such a
  rendering is a publication projection, and a signature over it stands over the projection.
- **Specific tools, executors, and cockpits** - the programs that produce or render records. kton
  *documents*; it does not execute or render.
- **Reference source code** - the plankton/nekton/kton implementations are licensed separately (Apache
  License 2.0); this specification governs the format and semantics that any implementation must meet.

Any changes of Scope are not retroactive.
