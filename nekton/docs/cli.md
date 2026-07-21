# CLI design - `plankton` & `nekton` as bash tools

> **Status:** design sketch (both repos are scaffolds). This is the intended command surface,
> consistent with the kernels in `spec/SPEC.md`. Output shown is illustrative.

## The hard invariant - read first

> **plankton is NEVER an executor. nekton is NEVER an executor or a reasoner.**
> Neither tool runs a protocol, opens a sandbox, executes a command, re-runs anything, or
> normalises/compares/infers. **All running lives in external executors** - separate binaries,
> registered by `kind`, in their own packages. plankton and nekton are *downstream* of every
> executor: they only **record, sign, verify (by hash/signature), and federate**.

If a command would *cause something to run*, it does **not** belong to `plankton` or `nekton`.
That is the whole point of the opaque protocol (`plankton`) and the opaque predicate (`nekton`).

```
   cockpits  (a workbench, CLI, web, paper)        ← orchestrate, decide UX
   ───────────────────────────────────────
   executors (external, by kind)               ← THE ONLY THINGS THAT RUN
     nonmem · r · psn · monolix · normalize · compare · tally · …
       │ emit fotons / verdicts (signed Statements)
       ▼
   plankton (record · verify · federate)   nekton (claim · template · federate)
       reproducible facts                      attestable commitments
```

## Principles

- **Thin over the kernel.** The CLIs only *record, sign, verify, federate*. They never execute.
- **Two write paths.** Either an **executor wraps** a run and hands plankton a foton, or you
  assert one **after the fact** (`record` / `observe`) - *"this did that"*. plankton runs nothing
  in either case.
- **Sign by default.** Every foton and claim is a DSSE envelope. `--sign <key>` required to write.
- **plankton's whole interface is: a signed Statement arrives → record it.** It has no executor
  concept; it never cares who produced a foton or how.
- **Hashes are the interface.** Everything in/out is `sha256:…`. Bytes live wherever they are.
- **Same federation verbs in both tools:** `serve`, `remote`, `sync`, `mirror`, `verify`.

Shared config: `~/.config/{plankton,nekton}/config.toml` → signing key, registry dir
(`--registry`), remotes, trust policy (whose signatures count).

---

## Executors - external, neither plankton nor nekton

Executors are where running happens. They are **separate tools**. a modeling workbench is one executor; a
neutral reference runner (here `runx`) is another; a `tally` executor is another. An executor's
job: take inputs + a protocol descriptor (incl. environment), **run it**, capture outputs, and
**emit a signed foton Statement**. It then hands that foton to plankton - which only records.

```console
# an EXECUTOR wraps the run (it owns the sandbox + the running). plankton is NOT invoked to run.
$ runx --kind nonmem \
       --in  raw/warfarin_conc.csv \
       --out 'modelfit_dir1/NM_run1/*.lst' --out 'modelfit_dir1/NM_run1/*.ext' \
       --env oci:acme/imrstudio@sha256:9f1c… \
       -- execute warfarin_PK.mod
runx: hashing inputs…   raw/warfarin_conc.csv sha256:f96b2717…
runx: running NONMEM in sandbox…   [output streamed]
runx: capturing outputs…  warfarin_PK.lst 048755ec…  warfarin_PK.ext babcae18…
runx: protocol.ref b7bab29b…  → wrote foton.dsse.json   (signed by the executor's key)

# plankton ONLY records what the executor produced - it ran nothing
$ plankton record --foton foton.dsse.json
✓ recorded foton:048755ec…@b7bab29b   completeness: fully-pinned + re-runnable
```

The same shape works piped: `runx … | plankton record --foton -`.

> **A workbench is an executor here.** When a workbench runs a step, it can emit the foton and
> pipe it to `plankton record`. plankton never reaches back into the workbench to run anything.

---

## plankton - record, verify, federate (it never runs)

```
# write path A - INGEST a foton an executor emitted
plankton record --foton foton.dsse.json          # or: --foton -   (stdin)

# write path B - assert after the fact ("this did that"), still no execution
plankton record --kind r \
                --in data/pk.csv --in scripts/fit.R \
                --out results/params.csv \
                --command scripts/fit.R --env renv:renv.lock
#   plankton hashes the EXISTING files and the descriptor and records the edge. It runs nothing.

# harvest from a flow tool that ALREADY ran (reads existing artifacts; no execution)
plankton observe --adapter snakemake .snakemake/   # also make|nextflow|cwl|bazel|ci

# files (pure metadata)
plankton hash PATH                  # -> sha256:…
plankton add  PATH [--pin]          # register {hash, uri}; --pin copies bytes to a blob store
plankton id   set "latest-clean" <hash>

# explore
plankton lineage  <hash|file>       # backward: what produced this, recursively
plankton uses     <hash>            # forward: fotons consuming this input (alt. scenarios)
plankton producer <hash>            # the foton whose output == hash, or "lineage root"
plankton ray      <hash> -o ray.json
plankton show     <foton-id>

# verify & federate - NO execution anywhere here
plankton verify  <hash|foton|ray>   # re-check content hashes + DSSE signatures (byte-level only)
plankton compare <foton-id> <output-tree>   # pure hash equality of a tree vs a foton's outputs
plankton serve   [--public] [--port 8787]
plankton remote  add origin https://reg.acme.example
plankton sync    origin             # conflict-free set union of append-only records
plankton mirror  origin [--pin]     # sync + persist (+ optionally pin bytes)
```

### What replaced `run` and `rerun` (the strict bit)

| tempting (WRONG) | strict reality |
|---|---|
| `plankton run -- <cmd>` | an **executor** runs; `plankton record --foton …` ingests the result |
| `plankton rerun <foton>` | the **executor** re-runs → emits new outputs; `plankton compare` checks the hashes; a **compare executor** (`kind=compare`) computes L0/L1/L2 and emits a *verdict* Statement that `plankton record` ingests |
| `plankton normalize` | a **normalize executor** (`kind=normalize`) does it; plankton stores the result by hash |

So a qualification re-run on the CLI is:
```console
$ runx --rerun foton:048755ec…@b7bab29b -o ./reproduced/        # executor re-runs
$ plankton compare foton:048755ec…@b7bab29b ./reproduced/       # plankton: pure byte equality
plankton: L0 byte-identical? no   (incidental fields differ)
# the L1/L2 verdict is NOT plankton's:
$ runx --kind compare --reference … --candidate ./reproduced/ --criteria normprofile… \
       -o verdict.dsse.json                                     # compare executor decides L1/L2
$ plankton record --foton verdict.dsse.json                     # plankton records the verdict
# accepting that verdict is nekton's job (below)
```

### Session - explore

```console
$ plankton lineage results/params.csv
results/params.csv  7be4…
└─ foton 7be4…@55aa  (kind=r)
   ├─ data/pk.csv   f3a1…  ← foton f3a1…@22bc (kind=clean)  ← raw/labs.xpt  ◦ lineage root
   └─ scripts/fit.R 9c20…  ◦ lineage root
```

---

## nekton - claim, template, federate (it never runs or reasons)

`nekton` writes **signed semantic claims** about files *and* executions (foton/ray hashes). It
ships a **federated set of annotation templates**. It does **not** reason over claims, resolve
ontologies, or tally votes - those are consumers / executors.

```
# the raw primitive
nekton claim --subject <hash|uri> --predicate <term> \
             [--object <hash|uri|k=v…>] [--context <term>] [--why "…"] [--evidence <ref>…] --sign KEY

# annotate via a TEMPLATE (the main path) - works on a file OR an execution
nekton annotate <hash|uri> --template <name> --set k=v [--set k=v…] --sign KEY

# convenience predicates (all = claim with a fixed term)
nekton confirm     <foton|ray>  --sign KEY [--why …]          # four-eyes
nekton review      <hash>       --sign KEY
nekton qualify-env <env-hash> --iq PASS --oq PASS --sign KEY
nekton equiv       <rayA> <rayB> --criteria <hash> --sign KEY # accept an L1/L2 verdict
nekton risk-accept <finding> --mitigation <ref> --sign KEY
nekton delegate    <to-id> --context <topic> --sign KEY
nekton vote        <motion> --choice <c> --context <topic> --sign KEY
nekton supersede   <claim-id> --sign KEY                       # append-only "retract"

# the federated TEMPLATES set
nekton templates ls | show <name> | search <kw>
nekton templates pull <remote> | push <remote> | add <file.json>

# explore / federate (same shape as plankton)
nekton claims --subject <hash> [--predicate …] [--signer …]
nekton show <claim-id>
nekton serve | remote | sync | mirror | verify
```

> **No `nekton tally` subcommand.** Tallying *runs* (resolve delegations, count) → that is the
> `kind=tally` **executor** `nekton-vote`, which ships *with* nekton but is a separate tool, not
> the kernel. The nekton kernel only **records** the `vote`/`delegate` claims and later
> **confirms** the result foton. See `executors/` and the loop below.

### Templates - the federated annotation kit

A template is a **content-addressed** JSON: which predicate term, which fields, and what it
**targets** - a `file`, a `foton` (execution), or `either`. nekton ships a starter set; you
`pull` more from peers or `add` your own. The kernel still prescribes nothing - templates are
convenient, shareable shapes over opaque `TermRef`s, and they federate like any record.

```console
$ nekton templates ls
NAME                TARGET   PREDICATE                       VOCAB        SOURCE
pmx/model-role      file     nekton/v/pmx/model-role         sha256:aa1…  bundled
pmx/dataset-kind    file     nekton/v/pmx/dataset-kind       sha256:aa1…  bundled
gxp/review          foton    nekton/v/confirmed              sha256:bb2…  bundled
gxp/tool-validation foton    nekton/v/validation-performed   sha256:bb2…  bundled
prov/derived-from   either   prov/wasDerivedFrom             sha256:cc3…  bundled
risk/accept         either   nekton/v/risk-accepted          sha256:dd4…  bundled

$ nekton templates show pmx/model-role
target:    file
predicate: https://kton.dev/v/pmx/model-role
context:   https://kton.dev/ctx/pharmacometrics
fields:
  role    enum[base, covariate, final, bootstrap, vpc]   required
  parent  ref                                            optional
vocab:     sha256:aa1…   (term definitions - federated by hash)

$ nekton templates pull origin             # templates federate like everything else
nekton: 3 new templates from origin
  + acme/submission-artifact  (foton)  sha256:ef5…
  + acme/qms-signoff          (foton)  sha256:ef5…
  + ddmore/model-provenance       (file)   sha256:9a7…
```

### Session - annotate a FILE, then an EXECUTION

```console
# semantic annotation of a file
$ nekton annotate sha256:048755ec… --template pmx/model-role --set role=base --sign alice
✓ claim:7c1d…  subject=file 048755ec…  role=base  context=pharmacometrics

# semantic annotation of the EXECUTION (subject = the foton, not its files)
$ nekton annotate foton:048755ec…@b7bab29b --template gxp/tool-validation \
    --set outcome=pass --set sop=SOP-PMX-014 --evidence sha256:protocol… --sign validator
✓ claim:9b8e…  “this tool validation actually happened, signed”

$ nekton confirm foton:048755ec…@b7bab29b --why "Reviewed per SOP" --sign bob
✓ claim:3f0a…  confirmed  (author alice ≠ confirmer bob)
```

### Session - accept a reproduction verdict

```console
# the L1 PASS itself was computed by a compare EXECUTOR and recorded in plankton.
# nekton only signs the ACCEPTANCE of it:
$ nekton equiv ray:REF… ray:CAND… --criteria sha256:normprofile… --sign qa-lead
✓ claim:1cc7…  identity-equivalent - the signed acceptance, not the computation
```

---

## The loop - vote → tally → confirm (three tools, strict)

```console
# 1. nekton: the signed inputs (nekton runs nothing - it just records claims)
$ nekton vote     motion:popPK-v3 --choice approve --context topic:popPK-approval --sign alice
$ nekton delegate did:example:alice --context topic:popPK-approval --sign bob
$ nekton delegate did:example:bob   --context topic:popPK-approval --sign carol
$ nekton vote     motion:popPK-v3 --choice reject  --context topic:popPK-approval --sign dave
# … eve/frank delegate in a cycle …

# 2. a TALLY EXECUTOR runs the deterministic count (external to BOTH tools)
$ nekton-vote --motion motion.json --roster roster.json \
             --ballots --since 2026-06-30T00:00Z \
             --method liquid-democracy@0.1 -o result.json
nekton-vote: sealed ballot box = 6 claims (input_set pinned by hash)
nekton-vote: approve=3 reject=1 winner=approve abstain={eve,frank}
nekton-vote: wrote result.json 138876cc…  → tally.foton.dsse.json (kind=tally, signed)

# 3. plankton records the foton (runs nothing); anyone can re-run via tally-exec and `plankton compare`
$ plankton record --foton tally.foton.dsse.json
✓ foton:138876cc…@99d69b54   completeness: fully-pinned + re-runnable

# 4. nekton confirms the outcome (subject = the tally foton)
$ nekton confirm foton:138876cc…@99d69b54 --why "Vote outcome ratified" --sign chair
✓ claim:…  - signed acceptance, next to the reproducible count
```

**nekton signs the inputs · a tally executor reproduces the count · plankton records it · nekton
confirms it.** No tool does a job that belongs to another layer.

---

## End-to-end story

```console
# 1. an EXECUTOR runs; plankton records (plankton never runs)
$ runx --kind nonmem --in raw/warfarin_conc.csv --out 'modelfit_dir1/NM_run1/*' \
       --env oci:…@sha256:9f1c… -- execute warfarin_PK.mod | plankton record --foton -

# 2. nekton says what it is (file + execution)
$ nekton annotate sha256:048755ec… --template pmx/model-role --set role=base --sign alice
$ nekton annotate foton:048755ec…@b7bab29b --template gxp/tool-validation --set outcome=pass --sign validator

# 3. prove (executor re-runs + compare executor decides) and accept (nekton confirms)
$ runx --rerun foton:048755ec…@b7bab29b -o ./repro/ && plankton compare foton:048755ec…@b7bab29b ./repro/
$ runx --kind compare --reference … --candidate ./repro/ --criteria … -o verdict.dsse.json
$ plankton record --foton verdict.dsse.json
$ nekton confirm foton:048755ec…@b7bab29b --sign bob

# 4. publish, federated
$ plankton ray sha256:048755ec… -o warfarin.ray.json
$ plankton serve --public ; nekton serve --public      # fotons, claims, templates all travel
```

A reader elsewhere, seeing only hashes, runs `plankton verify` (does it reproduce, by hash) and
`nekton claims --subject <hash>` (who called it a base model, who validated the tool, who
confirmed the result - each signed). Reproducible fact and attestable commitment, side by side,
both federated - and **nothing in plankton or nekton ever executed a thing**.

## Open CLI questions

1. **Executor discovery.** How do `plankton`/`nekton` know which executor serves a `kind` for a
   *re-run*? A local `executors.toml` registry mapping `kind → binary`, resolved by the cockpit -
   never by the kernels themselves.
2. **Key & identity UX.** `--sign <name>` → org-PKI (21 CFR Part 11 signers) vs a `nekton login`
   Sigstore-OIDC flow (open federation).
3. **Ballot sealing as a command.** `nekton motion close --cursor …` emitting a signed
   `motion-closed` claim that *names* the input set, so the tally executor's `--since` is accountable.
4. **One binary or two.** Separate `plankton` / `nekton` bins (layering visible on the CLI) vs a
   multi-call binary. Executors stay separate regardless.
