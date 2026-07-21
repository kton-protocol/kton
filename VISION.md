# Vision: plankton

> The light particles need a medium. plankton is the medium.

## The food chain

Science runs on transformations: data in, results out, and a record of how. Today
that record - when it exists at all - is locked inside whatever application produced
it. The transformation cannot travel. It cannot be verified by a stranger. It cannot
be reused by the next group, the next org, or the next model.

plankton inverts that. It is the **base of the food chain**:

- **plankton** - the particles. Files (content-addressed) and fotons (transformations)
  connected in a registry. Small, dense, drifting, everywhere.
- **fotons** - the light particles that move through it: a transformation is just
  `inputs -> protocol -> outputs`, all referenceable by hash and/or id.
- **whales** - the biggest animals. Big pharma submissions, regulatory review, large
  meta-analyses, AI systems that want a verifiable substrate to learn from and act on.
  They survive by filtering enormous volumes of plankton.

**We feed the whales.** A whale does not care which boat caught its food. It cares
that the food is abundant, clean, and trustworthy. plankton's job is to make
verifiable transformations abundant and recognizable - by hash, anywhere - so the
whales can feed without being tied to any one vendor's net.

## The second layer: statements about results

Reproducible results are half the story. The other half is what people *say* about them -
this reviewed, this qualified, this supersedes that. That layer is **nekton**: signed claims
about plankton results (and about other claims), rendered as nanopublications, ontology-agnostic
and federated. The dividing invariant is clean: a machine can **verify** a result (re-run / hash)
→ plankton; a person can only **vouch for** a statement (a signature) → nekton - and the
dependency is one-way, `nekton → plankton`. A reference cockpit, **kton**, conducts both layers
and reimplements neither. The stance is **composition, not invention**: plankton composes
in-toto/DSSE + content-addressing, nekton the nanopublication / Trusty-URI model; the new move is
the inert two-layer substrate and the bridge between a statement corpus and reproducible execution.

## What plankton is

A **registry connecting files identified by hash and/or id**, where a **foton** has
input files, output files, and a **protocol** that connects the transformation.

- A **file** is *what it is* (its content hash) and *which one it is* (its id).
- A **foton** is *how a set of files became another set* - an edge in the graph.
- A **protocol** is an opaque, content-addressed descriptor with a `kind`. plankton
  does not run it; external **executors** do, selected by kind.
- The **registry** is the resulting lineage graph - the substrate.

Because files are content-addressed, the same data is recognizable across galaxies
even when named differently. Because fotons record the connecting transformation,
lineage is complete by construction. Because the protocol is opaque, plankton stays
small and never grows back into the application it was extracted from.

## What plankton is not

- Not a cockpit. A cockpit flies this substrate. So can a CLI, a web
  app, a published paper's verifiable package, or another organization's tooling.
- Not an execution engine. It connects and verifies; it does not compute.
- Not a UX. No tree explorer, no dashboards. Those are cockpits.

## Why independence matters

If the substrate is tied to one application, it inherits that application's ceiling.
A cockpit is a *perfect way to navigate* - but a cockpit is not an ecosystem. For
the foton idea to succeed, the particles must be free of any single hull. plankton is
that freedom: a neutral, portable, content-addressed registry that any whale can feed
on and any cockpit can fly.

## Direction, not destination

The kernel is real; the frontier is adoption. Where things stand:

1. ✅ Data model pinned (files, fotons, refs, protocol kinds + environment, the registry graph).
2. ✅ A neutral **Go** reference - content-addressed registry + foton graph + DSSE + federation.
   No cockpit dependency. The **nekton** statements layer has its own Go reference alongside it.
3. ✅ An executor interface (Run+Record) so external runners fulfill protocols by kind (R, Python).
4. ◻ A transport/packaging format so fotons + their files travel across galaxies (federation sync
   + optional byte-pinning exist; a portable package is next).
5. ◻ Cockpits adopt it - a modeling workbench first, because it already speaks this language; a reference
   cockpit (**kton**) and a VS Code Navigator show the pattern.
