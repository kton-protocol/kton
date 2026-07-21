# security/ - the kton security regression suite

A machine-checkable regression gate built from the kton red-team engagement. Each attack is a short,
runnable PoC (`attacks/<id>.sh`) for a fixed finding; `check.sh` runs them all against the built binaries
and **fails CI if any previously-fixed attack becomes exploitable again**. "Is this build secure?" =
"does the gate pass?".

- `attacks/*.sh` - one runnable PoC per finding; each prints `VERDICT: PREVENTED | VULNERABLE`.
- `check.sh [kton-examples-dir]` - runs the gated attacks, prints a table, exits non-zero on any regression.
- `REPORT.md` - the full findings report (theory + vulnerable/fixed commit permalinks), rendered from the
  signed kton provenance graph. The signed graph + `nekton`-verifiable claims live at
  https://github.com/gitmick/kton-redteam .
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
