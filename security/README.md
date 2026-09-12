# security/ - the kton security regression suite

A machine-checkable regression gate built from the kton red-team engagement. `check.sh` runs the
attacks that have an executable reproduction against the built binaries and **fails CI if a finding
recorded as fixed becomes exploitable again**.

Read the gate for what it is: a green run means the attacks it executed still fail, not that the
suite is complete. `check.sh` prints its own coverage ratio for that reason - today it runs 10 of
28 recorded attacks. "Is this build secure?" is not answered by one line of output; the open
findings in REPORT.md are part of the answer.

- `attacks/<id>.sh` - the PoCs. Those that end in `VERDICT: PREVENTED | VULNERABLE | INCONCLUSIVE`
  are executable and are run by `check.sh`; **every one of them must appear in `GATED` or `OPEN`**, and
  `check.sh` fails if one does not. An executable PoC in neither list is invisible: nothing runs it,
  so `self-check.sh` cannot see it either, and it can rot into a script that proves nothing without
  anyone noticing (which is what happened to `fourEyes-graphpoll`).

  The rest carry no verdict and are **records of a finding**, with the reproduction in prose in
  REPORT.md. Thirteen of them are one-line notes. `normalizer-forge` is the exception: an executable
  *demonstration* of specified behaviour, which is why it has no verdict to give.
- `attacks/_records.sh` - shared store reader. A PoC must read the registry through it rather than
  globbing a layout, or a layout change reports as a fake regression.
- `check.sh [kton-examples-dir]` - runs the gated and known-open attacks, prints a table plus the
  coverage ratio, exits non-zero only on a real regression.
- `REPORT.md` - the full findings report (theory + vulnerable/fixed commit permalinks). It was
  rendered from the signed kton provenance graph, but neither the renderer nor the signed claims
  are in this repository, so it cannot be regenerated or `nekton verify`-ed from here. It is a
  hand-maintained document until that graph is published; treat it as prose, not as evidence.
- `redteam.pub` - the researcher public key (verify-only).

## Run locally
```
go build -o /tmp/bin/plankton ./reference/cmd/plankton
go build -o /tmp/bin/nekton   ./nekton/reference/cmd/nekton
go build -o /tmp/bin/kton     ./kton/reference/cmd/kton
PATH=/tmp/bin:$PATH bash security/check.sh /path/to/kton-examples
```

## In CI
The `security-regression` job in `.github/workflows/ci.yml` builds the binaries, checks out kton-examples
(for the viewer attack), and runs `check.sh`. A red gate names the exact finding that regressed.

## Scope
This gates the kernel/nekton/viewer-layer fixes (fast, deterministic, no R). Open items and accepted
boundaries are documented in REPORT.md, not gated.

**The example-12 gate attacks do NOT run anywhere else.** This file used to say they "run against the
full capstone in the kton-examples CI". They do not - that workflow builds the binaries, runs the
examples end to end and checks permalinks, and has no such step. Of the three it named:

| | |
|---|---|
| `fourEyes-graphpoll` | now executable, gated **here**, with three controls (it previously printed no verdict at all) |
| `spectrum-launder` | a one-line prose note in this directory; the reproduction is in REPORT.md |
| `normalizer-forge` | an executable demonstration of specified behaviour, no verdict to give; the property it points at is tested by example 12's Act 8a |

`envtally-CF2` is the fourth example-12 attack and runs here, in `OPEN`, because the shipped gate's
`env-qualified` condition reads the claim's own tally rather than the fulfilment it cites
(gitmick/kton-examples#14).
