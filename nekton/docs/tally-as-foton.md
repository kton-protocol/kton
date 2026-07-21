# Tally as foton - the nekton ⇄ plankton loop

How a vote/delegation count becomes a **reproducible** result without putting any voting logic
into either kernel. This is where the brainstorm's *"plankton as deterministic vote-aggregator"*
formally lands.

## The split, restated

- **nekton** holds the **signed inputs** - `vote` and `delegate` claims. *Attestable*: true
  because accountable identities signed them.
- **plankton** holds the **reproducible aggregation** - a `tally` foton: *given exactly these
  signed claims + this method, the count is X*. *Reproducible*: anyone re-runs and gets the
  same output hash.
- **nekton** then holds the **signed acceptance** - a `confirmed` claim about the tally foton.
  *Attestable* again.

Neither kernel learns about voting. nekton stays an opaque-predicate claim store; plankton
stays an opaque-protocol lineage store. The tally lives entirely in an **external executor**
(`kind: "tally"`), exactly like NONMEM or an R run.

```
   nekton claims                plankton foton                 nekton claim
  (vote / delegate)   ──▶   inputs → protocol{tally} → output   ──▶   confirmed(result)
   signed, attestable        reproducible by re-run               signed acceptance
        │                          │                                    │
        └── by hash ───────────────┴──── subject = foton hash ──────────┘
```

## The foton

```
inputs:   roster.json            # pinned eligibility + weights        (by hash)
          motion.json            # ballot: choices, topic, method      (by hash)
          ballots/*.dsse.json    # the SIGNED nekton claims, one file each (by hash)
protocol: { kind: "tally",
            ref:  sha256(descriptor),
            descriptor: { method:{id,version,rules}, env:{tool,version},
                          outputs_capture:["result.json"] } }
outputs:  result.json            # the tally + per-voter resolution     (by hash)
```

The claims enter the foton **as files, by hash** - the same `{hash, uri}` plankton already uses.
The DSSE envelope *is* the file; its bytes hash to the input ref. So the foton's inputs are the
**sealed ballot box**: change one claim, add one, drop one → different input set → different
`action_key` → a different, non-colliding foton. Tampering is not hideable.

The voting **rules live in `protocol.descriptor`** and are therefore inside `protocol.ref` and
the action key: a different method (different cycle handling, different tie-break) is a different
computation, not a silent re-interpretation of the same one.

## Determinism rules (what makes the output hash reproducible)

A tally is only a valid foton if it is a pure function of `(inputs + protocol)`. The reference
method `liquid-democracy/0.1` pins:

1. **Pinned input set.** The ballots are an explicit list of claim hashes - a *snapshot*, not
   "whatever is currently visible". (Sealing = choosing the cursor; see open questions.)
2. **Sorted voter order** (by identity) - no map-iteration nondeterminism.
3. **Direct vote overrides delegation.** A voter who voted directly is never delegated away.
4. **Delegation is topic-scoped.** Only `delegate` claims whose `context` == the motion topic count.
5. **Transitive resolution** until a direct vote is reached.
6. **Cycle / dangling → abstain.** A delegation loop with no direct vote, or a delegation to an
   ineligible/silent target, resolves to abstention - deterministically, no tie to wall-clock.
7. **Multiple claims by one voter:** latest `when`, tie-broken by **greatest claim hash**.
8. **Tie between choices → no winner** (explicit `winner: null`), never a coin flip.

No wall-clock, no randomness. Canonical-JSON output → stable SHA-256.

## Worked example (from `spike/tally_spike.py`)

Six eligible voters, weight 1 each. Claims:

| voter | claim | resolves to |
|-------|-------|-------------|
| alice | `vote approve` | approve |
| bob | `delegate → alice` | approve |
| carol | `delegate → bob` | approve (transitive) |
| dave | `vote reject` | reject |
| eve | `delegate → frank` | **abstain** (cycle) |
| frank | `delegate → eve` | **abstain** (cycle) |

Result: **approve 3, reject 1**, abstentions `{eve, frank}`, winner `approve`.

```
result.json   sha256:138876cc7993ca5d972819c462f384e1e3181e99a4c1522c55090251963312e6
protocol.ref  sha256:99d69b54cead755feeddfd38b6d3651df1c79b5e6733361aa08973e21a749a66
re-run hash matches: True
```

`result.json` also embeds the full per-voter `resolution` map and the `input_set` hashes, so the
output is self-describing: a reader sees *who resolved to what, and over exactly which sealed
inputs*. (The `via` field currently records the terminal step; recording the full delegation
path is a small refinement.)

The full in-toto Statement is `spike/tally_out/tally.foton.statement.json` - a plain
`https://kton.dev/foton/v0` foton, indistinguishable from a NONMEM foton to plankton.

## Why this is the whole point

- **No new trust, no new kernel feature.** Reuses plankton's foton wire form and nekton's claim
  wire form unchanged. The executor is just another `kind`.
- **The count is auditable by re-execution**, not by trusting the counter. A regulator pins the
  ballot box (the input hashes) and re-runs; a mismatch is detectable to the byte.
- **The inputs remain individually accountable.** Each ballot is a signed nekton claim - you can
  verify *who* voted/delegated and *that they were eligible*, independent of the count.
- **Acceptance closes the loop in nekton.** Ratifying the outcome is a `confirmed` claim whose
  subject is the tally foton's hash - attestable, four-eyes, GxP-shaped - sitting right next to
  the reproducible count it accepts.

## Open questions

1. **Sealing the ballot box.** Who pins the input set, and when? Options: a `motion-closed`
   nekton claim that *names the cursor/snapshot*, or a registry `sync?since=T` boundary. The
   seal itself should be a signed claim so it is accountable.
2. **Eligibility over time.** The roster is pinned by hash, but eligibility may change between
   motions - version rosters as content-addressed files and reference the right one per motion.
3. **Weight delegation vs. vote delegation.** v0.1 delegates a whole voter; weighted/partial
   delegation is a method extension (new `method.version`, hence a new protocol, by design).
4. **Privacy.** Open ballots here (every claim is signed and visible). Secret ballots would need
   a different method (commitments / blind signatures) - a separate `kind`/method, not a kernel change.
5. **Recording the delegation path** in `resolution` (full chain, not just terminal step) for richer audit.
