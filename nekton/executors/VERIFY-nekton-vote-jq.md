# Verification note - nekton-vote.jq (zero-Python build)

Ran the flagged "run for real on a real machine" check (INDEX/OPEN-QUESTIONS item).
Environment: Ubuntu 24.04 (WSL), jq 1.7, openssl (Ed25519), bash+coreutils.

- 2026-07-01: first run, determinism.
- 2026-08-13: re-run after the round-2 C1 change (count by VERIFIED signing keyid), including an
  adversarial ballot and a cross-check against the canonical `nekton-vote`.

## Determinism: PASS (the ⚠ is cleared)
- Two identical runs → **byte-identical** `tally.foton.statement.json`, `tally.foton.dsse.json`
  (Ed25519 is deterministic), and `result.json`. No wall-clock, no randomness. Re-confirmed 2026-08-13
  with `--keys` in the path.
- Tally correct: **approve=3, reject=1, turnout=4, winner "approve"**; `eve`/`frank` abstain via the
  delegation cycle (cycle-or-dangling). Matches the INDEX expectation.

## Signature verification (round-2 C1): PASS
Fixture: three roster voters keyed by `nekton keygen`, ballots authored with `nekton claim`, plus a
fourth ballot signed by `mallory` (not on the roster) carrying `by: <alice's keyid>` and a **later**
`when` - which under "latest when wins" would have replaced alice's vote.

- Without the fix (the file as it stood on `main`): the forged ballot **counted as alice** and flipped
  the outcome, approve=1/reject=2, winner "reject".
- With the fix: the forged ballot verifies against no eligible key and is **dropped**. alice's own
  vote stands, approve=2/reject=1, winner "approve", turnout 3 out of a 4-file ballot box.
- The canonical `nekton-vote` drops it too, on the same fixture.

## Key format: BOTH hex and PEM are accepted
`--keys` reads the eligible voters' public keys. `nekton keygen` writes `<name>.pub` as **64 hex
chars**; this executor's own key material is openssl **PEM** (README: `--sign key.pem`). The first
cut of the fix read PEM only, so a directory of `nekton keygen` keys made `openssl pkey` fail, the
failure hashed the resulting empty output to the sha256 of the **empty string** (one plausible-looking
keyid for every key), and `pipefail` then aborted the run with no diagnostic at all. Both encodings
are now accepted and yield identical results; an unreadable key is a hard error, and an empty
`--keys` directory is refused rather than tallying every ballot as dropped.

Note the asymmetry: the canonical `nekton-vote` reads **hex only** (`bytes.fromhex`). The `.jq` build
is a superset, so a roster is portable to it but not necessarily back.

## Still NOT byte-compatible with the canonical `nekton-vote`
The two builds agree on the **semantic result** (same tally, same winner, same dropped ballot) but
emit **different foton ids**. Re-checked 2026-08-13 on one shared fixture:

1. **`motion`/`roster` are pinned differently** - the `.jq` build hashes them as **raw bytes**, the
   canonical build uses `nekton-codec canon-hash` (JCS). Same file, two ids
   (`fc90356f…` vs `2f241c24…`). Ballots are raw-hashed in both. *(New; supersedes the 2026-07-01
   "inputs[] ordering" entry, which was the same symptom read from the old output shape.)*
2. **`protocol.ref` still differs** (`48a50c53…` vs `034d48ba…`), now only through descriptor key
   order and whitespace - the earlier cause, a `nekton-vote` / `nekton-tally` tool-identifier split,
   **is resolved**: both say `"tool":"nekton-vote"`.

## Recommended fix (defer to M1/M3 conformance work)
- Decide **one** rule for pinning `motion`/`roster` - raw bytes or canon-hash - and apply it in both.
- Freeze the descriptor's **byte layout** (key order) so `protocol.ref` agrees.
- Regenerate the shipped reference vectors from the canonical implementation; add them to the frozen
  conformance vector set (fixed key).

Until then: the zero-Python path is safe to use standalone (internally deterministic, and it
authenticates its ballots); just don't expect its foton id to equal the canonical build's.
