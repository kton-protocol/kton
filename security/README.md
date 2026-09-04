# security/ - the kton security regression suite

A machine-checkable regression gate built from the kton red-team engagement. `check.sh` runs the
attacks that have an executable reproduction against the built binaries and **fails CI if a finding
recorded as fixed becomes exploitable again**.

Read the gate for what it is: a green run means the attacks it executed still fail, not that the
suite is complete. `check.sh` prints its own coverage ratio for that reason - today it runs 10 of
28 recorded attacks. "Is this build secure?" is not answered by one line of output; the open
findings in REPORT.md are part of the answer.

- `attacks/<id>.sh` - the PoCs. Those that end in `VERDICT: PREVENTED | VULNERABLE` are executable
  and can be gated; the rest are records of the finding whose reproduction lives in prose in
  REPORT.md or in the kton-examples capstone CI.
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
This gates the kernel/nekton/viewer-layer fixes (fast, deterministic, no R). The example-12 gate attacks
(four-eyes, spectrum-launder, normalizer-forge) run against the full capstone in the kton-examples CI.
Open items and accepted boundaries are documented in REPORT.md, not gated.
