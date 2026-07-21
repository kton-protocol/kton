# Reproduction identity - when are two results "the same"?

Byte-equality is the wrong test for reproduction. A correct NONMEM re-run is **never**
byte-identical: the output embeds the **licensee**, **run date/time**, **elapsed time**,
**hostname**, **file paths**, and a **version banner** - all incidental - and the numeric
estimates legitimately differ (floating point, BLAS, CPU). So plankton needs an explicit
**equivalence relation coarser than byte-equality** to decide reproduction and
qualification.

This is the reproducible-builds problem (normalization: `SOURCE_DATE_EPOCH`,
`strip-nondeterminism`, `diffoscope`) plus numeric tolerance.

## Key simplification: normalization is itself a foton

Equivalence is **not** a kernel primitive. The kernel knows exactly one equality: **raw
hash (L0)**. Everything richer is composition:

- **L1** = append the **same normalization foton** to both outputs and compare the
  **terminal hashes**. "The end of the ray has the same result." L1 is just L0 measured
  at the end of a normalization ray.
- **L2** = a **comparator foton** `C(reference, candidate, tolerance-spec) → verdict`.
  The verdict is a file with a hash; "did it reproduce?" = "does a comparator foton exist
  whose verdict says PASS." The verdict is addressable and reproducible like anything
  else.

The **normalization profile** and **tolerance spec** are just **input files** to those
fotons. Two computations are equivalent iff their rays **converge** - terminal hashes
meet. So the "canonical hash" below is not a new kernel field; it is simply the raw hash
of the *output of a normalization foton*.

**There is no hard L1/L2 boundary in the kernel** - the split is presentational. A *strip-only*
normalization foton yields identity-after-stripping (the table's L1); a normalization foton that
*also rounds numerics to a declared precision* turns a tolerance comparison into the same
identity-after-normalization (the table's L2) - and because the rounding lives **inside** a
content-addressed normalization foton, it is fully inspectable, never a hidden policy. So the only
real primitive is **(public, declared normalization foton) + raw-hash identity**; L0/L1/L2 are
three points a consumer may pick on that one continuum, accepted (or not) via their trust filter.
plankton neither computes nor judges this.

## Three levels of identity - an *example*, not a kernel definition

> **What plankton actually specifies is minimal:** raw-hash equality (L0), plus the fact that
> *any* coarser equivalence is just **L0 measured at the end of a normalization foton**. The
> L0/L1/L2 ladder below is **one illustrative convention** - useful, and what NONMEM-style
> qualification tends to use - but the kernel does **not** mandate these levels, name them, or
> fix their boundaries. A cockpit, executor, or consumer may adopt, refine, or ignore them.
> plankton specifies *(declared normalization foton) + identity*; everything else here is example.

A coarsening relation; a reproduction is certified at the **highest level it reaches**.

| Level | Test | Used for | NONMEM |
|------|------|----------|--------|
| **L0 byte-identical** | raw content hash equal | storage, integrity, dedup | ~never |
| **L1 canonically-identical** | equal after a named **normalization** (strip incidental fields) → a **canonical hash** | reuse + comparison of non-byte-stable outputs | removes licensee/date/path/banner noise |
| **L2 semantically-equivalent** | parsed results within a declared **tolerance**; structural/categorical fields exact | qualification of estimation tools | estimates/OFV/SE within tolerance |

A verdict records: the level reached, the criteria used (by id), and the **residual diff**
(what differed, and whether it was ignored (L1) or in-tolerance (L2)).

## Two addresses per file

- **Raw content hash** - always present; *what the file literally is*. Integrity, dedup,
  audit.
- **Canonical hash** (optional, per normalization profile) - *what it means for
  reproduction*; what lets a non-byte-stable output be matched/reused at all.

So a file/output may match nothing at L0 yet match cleanly at L1, or only at L2.

## Criteria are first-class, content-addressed, versioned, signed

A **normalization profile** and a **tolerance spec** are themselves hashed, immutable
artifacts, keyed by `protocol kind` + file role:

```
NormalizationProfile := { kind, role, rules[], version, hash }
  e.g. kind=nonmem, role=.lst : drop header lines matching /Licensed to/, /^Date:/,
       /elapsed/, absolute paths, NM-version banner
ToleranceSpec        := { kind, role, fields[]→tol, version, hash }
  e.g. estimates rel-tol 1e-4, OFV abs-tol 0.01, SE rel-tol 1e-2
```

Why this matters for GxP: declaring *exactly which differences are non-meaningful and
why* **is** an OQ acceptance criterion. Making the criteria immutable + versioned +
signed means the qualification verdict is fully reproducible and auditable - you can show
the regulator precisely what was compared, what was ignored, and what tolerance was
accepted.

## How a qualification run uses this

```
reference foton  (known-correct outputs)
  + re-run foton (executor produces new outputs)
  + equivalence criteria (normalization profile id + tolerance spec id, both signed)
  → verdict: PASS@L2 / FAIL, with residual diff
```

A PASS is durable qualification evidence (F7.4). Comparison is always **like-for-like**:
same tool version + estimation method, or the verdict is downgraded to "consistency", not
"reproduction".

> **Layer note.** The comparator (`kind=compare`) and its verdict *file* are a **plankton**
> foton - a machine-verifiable result. **Accepting** that verdict as a qualification -
> signing "this ray meets OQ criteria C" - is a **nekton** claim over the verdict's subject
> hash, not a plankton record. Mechanical comparison → plankton; signed acceptance → nekton
> ([../nekton/spec/SPEC.md](../nekton/spec/SPEC.md), [attestation.md](attestation.md)).

## Spectrum - a tool/environment validation (an application of the above)

A **spectrum** is a named application of reproduction identity to validate a *tool or
environment*: a set of **reference fotons** plus a **normalization foton**, where conformance
means *this environment reproduces the reference fotons and, after the normalization, the outputs
are identical*. It is the executable definition of "this is a valid NONMEM 7.x / a valid
xpose-style diagnostic / a valid translator".

- **Seeded from what already exists** - a tool's *own test suite* (or an open conformance set)
  becomes its spectrum; register the references, don't author new ones.
- **Deterministic vs estimating tools** - deterministic potentials (translators, parsers,
  visualisers, reformatters) reproduce *identically*, so a strip-only spectrum suffices;
  estimation engines' numeric estimates do not byte-reproduce (FP), so numeric agreement is a
  separate tolerance comparison, not forced into a strip-only spectrum.
- **Self-application** - a *conformance suite for a plankton implementation itself* is a spectrum:
  reference fotons + a normalization that any conformant implementation must reproduce identically.
  (This is the one hard lever a governance body needs - "plankton-compatible" = passes the spectrum.)

A spectrum is still just fotons + a normalization + identity; plankton stores it and lets you query
it, and **never says which spectrum is "correct"** - that is the consumer's choice.

> **Where it is used (term ownership).** plankton defines only the spectrum *mechanism* (reference
> fotons + normalization + `reproduces`). The *qualification* application - validating a tool
> instance against a spectrum, then using the qualified environment as part of an execution-cache key
> - is a cockpit's concern, defined in its own tool-qualification spec. One term, defined once here,
> applied there; plankton neither qualifies nor judges.

## Knock-on effects elsewhere

- **Discovery (F10.2):** "same result across tools" means same **canonical/semantic**
  form (L1/L2), *not* same raw hash (L0) - tool outputs almost never share raw bytes.
- **Reuse:** reuse by raw hash (L0) is unconditionally safe; reuse by canonical hash (L1)
  is safe only relative to a trusted, signed normalization profile.
- **Foton completeness (F9.4):** L2 qualification needs a re-runnable, version-pinned
  foton; lineage-only fotons can still be compared structurally where outputs are parsed.

## Open questions

- Per-kind catalog of normalization profiles + tolerances - who authors and approves
  them (a qualification cockpit, presumably), and how are they peer-reviewed?
- Does the canonical hash live in plankton, or is normalization a cockpit/executor
  concern that merely *publishes* a canonical-hash claim back to the foton? (Leaning:
  plankton stores raw hash + accepts signed canonical-hash + criteria-id claims; it does
  not itself normalize - consistent with "plankton does not execute".)
