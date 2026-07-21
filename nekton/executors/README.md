# nekton executors

## The asymmetry - read first

**plankton has no executor concept.** Its entire interface is: *a signed Statement arrives,
plankton records it.* plankton does not define, discover, invoke, or know about executors. It
never cares *who* produced a foton or *how*. Statements in, lineage out. That is the whole of it.

**nekton needs to run the vote.** A tally is not a signed assertion you can just write down - it
has to be *computed* (resolve delegations, count). So the nekton distribution **ships a concrete
executor for it**: `nekton-vote`. The nekton *kernel* still runs nothing; this companion tool
does the running, and its output is - of course - a plankton Statement.

```
nekton claims (vote/delegate)          nekton-vote  (THIS - a bash executor)
   signed, recorded by nekton    ──▶   resolves + counts, deterministically
                                              │ emits a signed foton Statement (kind=tally)
                                              ▼
                                        plankton record   ──▶  "a Statement arrived. recorded."
                                              ▲
                                        nekton confirm(result foton)   ← signed acceptance
```

So: **nekton signs the inputs · `nekton-vote` reproduces the count · plankton records the
Statement · nekton confirms it.** No layer does another layer's job. plankton's view of the whole
affair is one line: *a foton Statement was recorded.*

## `nekton-vote`

A bash executor. CLI + the liquid-democracy resolution logic are pure bash; JSON canonicalisation
and DSSE Ed25519 signing are delegated to the swappable `nekton-codec` helper (in production: `jq`
+ `openssl`). It runs nothing else and writes to no registry - it only emits a Statement.

```
nekton-vote --motion m.json --roster r.json --ballots DIR \
            --method liquid-democracy@0.1 --sign key.pem -o result.json
```

Inputs (all content-addressed):
- `motion.json` - id, choices, topic, method
- `roster.json` - eligible voters + weights
- `--ballots DIR` - the **sealed ballot box**: signed nekton `vote`/`delegate` claim DSSE files

Outputs:
- `result.json` - the tally + per-voter resolution + the pinned `input_set` hashes
- `tally.foton.statement.json` - the in-toto `kton.dev/foton/v0` Statement (kind=tally)
- `tally.foton.dsse.json` - that Statement, **DSSE-signed** → hand to `plankton record --foton -`

### Determinism (so plankton can re-run and get the same output hash)

Sorted voter order · direct vote overrides delegation · topic-scoped delegation · transitive
resolution · cycle/dangling → abstain · multiple claims by one signer = latest `when` then
greatest hash · canonical-JSON output. No wall-clock, no randomness.

### Verified run

Scenario: alice votes approve; bob→alice; carol→bob (transitive); dave votes reject; eve↔frank
(delegation cycle → abstain).

```
nekton-vote: tally        approve=3 reject=1
nekton-vote: winner       "approve"   abstain=eve frank
nekton-vote: result.json  sha256:2ec5043a…
nekton-vote: emitted      tally.foton.dsse.json  (kind=tally, signed)

re-run foton hash:    sha256:009edfe5…   (identical across runs ✓ deterministic)
DSSE signature:       VALID over PAE; keyid 5e9f1490c2ddbd94 ✓
foton predicateType:  https://kton.dev/foton/v0   kind=tally   inputs=8
```

Running the executor produces a `result.json`, the foton Statement, and the signed envelope -
exactly what `plankton record` would ingest.

## Two builds of the executor

| file | dependencies | tested here |
|------|--------------|-------------|
| `nekton-vote` | bash + `nekton-codec` (Python shim) | ✅ fully |
| `nekton-vote.jq` | bash + `sha256sum` + `base64` + `openssl` + **`jq`** (jq used *only* to parse claim payloads) - **zero Python** | ✅ logic+crypto verified; the `jq` calls were exercised via a faithful stand-in because jq isn't installable in this offline sandbox |

Both emit byte-identical-in-spirit signed fotons. The hardened `.jq` build relies on a key fact:
per the plankton spec, **input files are hashed as raw bytes** and `result.json` / the foton
Statement are hashed and **signed over their literal bytes** - so no canonical-JSON library is
needed. Determinism comes from a **fixed emission layout** (sorted voters/choices/inputs), not
from a canonicaliser. `jq` is therefore needed for exactly one job: reading the signed claim
payloads. Verified properties of `nekton-vote.jq`:

```
deterministic:  result.json AND foton bytes identical across runs ✓
signature:      openssl Ed25519 over DSSE PAE, verified independently ✓ (keyid d8bbba16…)
integrity:      signed bytes == statement file bytes; result raw-hash == foton subject digest ✓
```

## `nekton-confirm` (in ../cli/) - closing the loop, zero dependencies

`nekton-confirm` is **not** an executor - it computes nothing, it writes one signed nekton
`confirmed` claim about a subject (typically the tally foton). bash + openssl + sha256sum, **no
Python, no jq**. Its hand-emitted claim JSON is byte-identical to canonical form (verified).

```console
$ nekton-confirm --foton tally.foton.dsse.json --by "CN=Board Chair" \
                 --why "vote outcome ratified" --sign chair.pem -o claim.confirmed.dsse.json
✓ signed nekton claim; subject = sha256(tally foton); predicate = confirmed
```

This is the final step of the loop: **nekton records the votes · `nekton-vote` reproduces the
count · plankton records the foton · `nekton-confirm` signs acceptance.**

## Why the codec is split out (for `nekton-vote`)

`nekton-codec` exists only so the *logic* stays readable bash. It does a few things - extract a
claim's fields, hash, build the foton Statement, sign DSSE. The `.jq` build inlines those with
`jq`/`openssl` instead. The split is a porting seam, not architecture.

## Files

```
executors/
  nekton-vote        # bash executor (logic) + nekton-codec  (Python shim - tested fallback)
  nekton-vote.jq     # hardened: jq + openssl + coreutils, ZERO Python
  nekton-codec       # JSON/crypto shim used by nekton-vote
cli/
  nekton-confirm     # sign acceptance of a foton - zero dependencies
```
