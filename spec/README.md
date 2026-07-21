# spec/

Formal schemas for File, Foton, Protocol, and the registry/federation API. plankton is
**results-only**: it records fotons (reproducible results). Signed *claims about* fotons -
verdicts, environment/tool qualification, reviews - are **nekton** records
(`../nekton/spec/SPEC.md`), not plankton predicate types. The cut: machine-verifiable (re-run/hash)
→ plankton; human-vouched (signature) → nekton; dependency nekton → plankton.

- **[SPEC.md](SPEC.md)** - the unified **kton v0.1** specification (Pre-draft): both layers
  (plankton results + nekton attestations) in ISO/Community-Specification structure, normative where
  stable, with each conformance scenario mapped to a clause. The contract two implementations must
  agree on.

Rationale and design discussion live in [`../docs/`](../docs/); conformance vectors live in
[`../reference/testdata/`](../reference/testdata/).

## License & governance

The **normative specification** in this directory is licensed under the **Community Specification
License 1.0** - not the code's Apache 2.0, and not CC BY - because a specification's licence must grant
*independent implementers* the copyright and patent terms they need. It is developed under the Linux
Foundation / Joint Development Foundation **Community Specification** framework; its scope, license,
governance, and contribution rules live in [`../community-specification/`](../community-specification/)
(setup in progress - until finalized the spec is `Pre-draft` and provisional).
