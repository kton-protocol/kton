# Semantics & perspectives - meaning lives *outside* the kernel

plankton stores **no semantics**. The kernel knows files (`{hash, uri, id?}`) and fotons
(`inputs → protocol → outputs`) - and derives only what the environment forces (e.g.
`kind=monolix`, a tool version). (Signed *claims* about these results are the separate **nekton**
layer, keyed by subject hash - [../nekton/spec/SPEC.md](../nekton/spec/SPEC.md); they too carry no
semantics the kernel interprets.) It never knows that a file *is* a "Monolix
populationParameters.txt", what a dataset's columns *mean*, or which of two cleanings is *better*.
All of that is **perspective**, and it is deliberately kept out of the substrate.

## The semantic index is a perspective, exported by a cockpit

A cockpit (a modeling workbench is one) holds rich metadata - dataset variables, tool category / tool / tool
instance, model structure - and **exports a semantic index** that points at plankton objects **by
hash/id**. This follows **Linked Open Data**: the content hash is the subject; statements about it
are RDF-style triples (or a plain `hash → tags` map - the implementation is free, hashmap or triple
store). The substrate is never touched; the index merely *references* it.

### Scope rule - the index reuses content-addressing for scope
- A statement on a **file hash** applies to **every use of those bytes**, anywhere in the
  federation (intrinsic facts - "these bytes are a Monolix `populationParameters.txt`").
- A statement on a **specific foton** stays **local to that use** (contextual facts - "in this run
  the estimation diverged", "this run is the approved reference").

The discipline: intrinsic facts on the file, usage/context facts on the foton - or a
context-specific claim leaks globally.

### Semantics federate exactly like files do - by hash
Two organisations' indexes about the same bytes share a subject (the hash), so they **merge
automatically** (LOD same-subject), and a consumer queries the **union they trust** with the same
trust filter used for registries. Substrate federates by hash; meaning federates by hash; one trust
model spans both. **Competing ontologies overlay rather than fight** - useful predicates win by
adoption, not by decree. There is no canonical vocabulary anyone must ratify.

## Perspectives - every view over (substrate + semantics)

A **perspective** is any view computed over the registry and/or the semantic index. None are part
of the kernel; all are composed outside it:
- **Matrix** - run the same model across backends/translators/extractors/visualisers and show the
  results side by side. Any PASS/FAIL or tolerance comparison is itself a perspective carrying an
  explicit, contestable tolerance artifact - never baked into the record.
- **Spectrum verdicts** - see `reproduction-identity.md` (tool/environment validation).
- **Dashboards, compare-fotons, reports** - e.g. "compare two aggregations and explain the
  differences". The substrate makes the disagreement *navigable*; the perspective never crowns a
  winner.
- The **display export** (`reference/cmd/plankton/export.go`) is itself a perspective: a graph JSON
  a navigator can draw. It is **not** an interchange format and **not** the foton wire form.

## Reuse vocabularies/formats *here*, never in the kernel

The "assemble, don't reinvent" rule (`novelty-and-build-vs-assemble.md`) applies to this layer too -
but these belong to the **perspective layer**, matched-against or exported-to, and **never become
part of plankton**:
- **ProbOnto** - distribution/parameterisation vocabulary (variance vs SD vs precision, log-scale).
  Reference data that doesn't rot; it *matches in a filter/dashboard*, it is never in the substrate.
- **W3C PROV / PROV-O** - lineage interchange vocabulary (Entity≈file, Activity≈foton, Agent≈org).
  A plankton view *exported as* PROV is readable by any PROV consumer across science.
- **RO-Crate (+ Workflow-Run profile)** - JSON-LD packaging of a run as a portable object; a natural
  serialization of a perspective for the FAIR/WorkflowHub world.

A PROV/RO-Crate exporter is a **separate perspective-layer artifact** - distinct from `export.go`
(display) and from the foton wire form (in-toto Statement). None of ProbOnto/PROV/RO-Crate is a
kernel component; the kernel's standards footprint stays the four in SPEC 2: RFC 8785 (JCS),
in-toto Attestation v1, DSSE, and SHA-256/multihash.
