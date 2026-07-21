# Verification note - nekton-vote.jq (zero-Python build)

Ran the flagged "run for real on a real machine" check (INDEX/OPEN-QUESTIONS item).
Environment: Ubuntu 24.04 (WSL), jq 1.7, openssl (Ed25519), bash+coreutils. Date: 2026-07-01.

## Result: PASS on determinism (the ⚠ is cleared)
- Two identical runs → **byte-identical** `tally.foton.statement.json`, `tally.foton.dsse.json`
  (Ed25519 is deterministic), and `result.json`. No wall-clock, no randomness.
- Tally correct: **approve=3, reject=1, turnout=4, winner "approve"**; `eve`/`frank` abstain via the
  delegation cycle (cycle-or-dangling). Matches the INDEX expectation.

## New finding: NOT byte-compatible with the shipped Python reference
The jq build and the Python `nekton-vote` agree on the **semantic result** but emit **different foton
IDs**. Two root causes, both trivial-but-real:

1. **`inputs[]` ordering differs** - jq emits `ballots/* … , motion.json`; the Python reference emits
   `motion.json, ballots/* …`. Different array order → different statement bytes → different foton id.
2. **Embedded tool name differs** - jq descriptor says `"tool": "nekton-vote"`; the Python reference
   says `"tool": "nekton-tally"`. → different `protocol.ref` (jq `sha256:48a50c…` vs ref
   `sha256:99d69b…`), hence different output hash (`a593e4…` vs `138876…`).

## Recommended fix (defer to M1/M3 conformance work)
- Freeze **one canonical input ordering** (sorted by relative name) in BOTH implementations.
- Reconcile the **tool identifier** (one of `nekton-vote` / `nekton-tally`) across both.
- Regenerate the shipped reference vectors from the
  canonical implementation; add them to the frozen conformance vector set (fixed key).

Until then: the zero-Python path is safe to use standalone (internally deterministic); just don't
expect its foton id to equal the Python reference's.
