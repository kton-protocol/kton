# Executor adapters - the pluggable-environment contract

plankton does not execute. The cockpit/CLI "planktons" a run by handing it to an **executor
adapter** chosen by file type. Adding a language or environment = adding an adapter; nothing in
the kernel changes. This is how R, Python, NONMEM, Docker, and remote backends (Posit) all plug in.

> **Status: this document specifies the contract; no adapter ships in this repo.** That is the
> design, not a gap - `docs/decisions.md` §3 puts *all* running in executors, which are separate
> tools outside the substrate. What follows is therefore the interface an adapter must implement and
> two worked-out designs for it, not a description of files you will find here. The paths named
> below are illustrative.

## The contract

An adapter is any executable with this interface:

```
<adapter> <job> <workdir> <manifest-out> [job args...]
```

It **runs** the job in `workdir`, **observes** the files it reads and writes, **captures** the
environment, and writes a **run manifest** to `manifest-out`:

```json
{ "kind": "rscript",                 // protocol kind -> the foton's protocol.kind
  "inputs":  ["/abs/path/read.csv"], // files the run READ
  "outputs": ["/abs/path/out.json"], // files the run WROTE
  "envkind": "renv",                 // environment kind (F4.3): renv | python-lock | oci | nix | ...
  "env":     "/abs/path/lock.json" } // the content-addressable environment descriptor
```

A **dispatcher** does the rest, identically for every adapter, so that work is written once rather
than per language: a directory-diff backstop for outputs, then spec assembly (relative paths, the job
and env as inputs, the environment pinned in the protocol), then `plankton author` + `plankton add`.
The job script and the environment lock are **always** inputs; the environment is pinned in
`protocol.environment`.

## Two adapters worked out

Designs, not shipped files - each shows how a runtime can be made to report what it actually touched.

| Adapter | runs | observes I/O | environment (`envkind`) |
|---|---|---|---|
| **R** | `Rscript` | wraps `read.*`/`write.*`/`readLines`/`writeLines`/`*RDS` + dir-diff | `renv.lock`, else session packages (`r-session`) |
| **Python** | `runpy` | `sys.audit('open')` hook (PEP 578) + dir-diff | installed distributions (`python-lock`) |

Planned (same contract): **nonmem** (inputs = ctl + dataset; carries the *normalization foton* that
strips license + date - the qualification example), **docker** (run by image digest; bind-mount
dir-diff; `envkind: oci`), **posit** (remote/managed environment: submit → fetch artifacts →
capture session env - the generic interface for any cloud/HPC backend).

## Why this shape

- **Language-agnostic & external** - keeps "executors are external"; an adapter is just a script
  that emits a manifest, so a new runtime is a drop-in.
- **Observe, don't declare** - the run reports what it *actually* touched (no manual input/output
  lists), so the lineage is honest. Where a runtime can declare I/O statically (e.g. a typed
  pipeline language), the adapter can skip the tracing.
- **Cross-environment lineage is automatic** - an R run writing `canonical.json` and a Python run
  reading it splice by hash in one registry, with no coordination between the two runs and no shared
  tooling. Neither adapter knows the other exists; the hash is the whole interface.

## What a session looks like

Illustrative - it shows the shape, and the last line is the point:

```
<dispatch> theo-fit.R      # R:      theo.csv      -> canonical.json
<dispatch> report.py       # Python: canonical.json -> report.txt
plankton lineage <report.txt hash>
# report.txt <- python <- canonical.json <- R <- theo.csv
```

The lineage spans two languages and two environments because both runs recorded the same hashes,
not because anything joined them up.
