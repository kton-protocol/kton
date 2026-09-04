#!/usr/bin/env bash
# cursor-shift: a record added AFTER a peer has synced is never delivered to that peer.
#
# SPEC §12's sync(since) hands a peer a cursor and promises that everything newer comes back on
# the next call. The cursor was a record's RANK IN THE HASH-SORTED STORE, recomputed on every
# load - not a position issued once. Hash order has nothing to do with append order, so a new
# record lands wherever its hash happens to fall: only one that sorts LAST gets a number above
# the peer's cursor. Every other one is born below it and is invisible forever.
#
# That makes it an attack as well as a bug. A record's hash is grindable (change a byte of the
# payload, rehash), so anyone able to write a record into a store - a git merge is a documented
# federation transport - can pick one that sorts early and have it, or the honest record it
# displaces, silently withheld from every already-synced peer. Roughly (N-1)/N of new records
# are lost by accident, so ~2 attempts suffice to place one deliberately.
#
# The fix (AUD-02) issues a position ONCE, at append time, into objects/.seq beside the records,
# and never recomputes it. This PoC asserts the property that matters, not the mechanism: after
# syncing to the cursor, adding one record MUST make exactly that record appear above it.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
command -v jq       >/dev/null 2>&1 || { echo "VERDICT: N-A (no jq)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A (no temp dir)"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }

ROUNDS=8
missed=0
for round in $(seq 1 $ROUNDS); do
  R="$W/r$round"; mkdir -p "$R"
  export PLANKTON_DIR="$R"
  plankton keygen k >/dev/null 2>&1
  # A peer syncs a store of three records and stores the cursor it was handed.
  for i in 1 2 3; do
    printf 'seed-%s-%s' "$round" "$i" > "in$i"; printf 'out-%s-%s' "$round" "$i" > "o$i"
    plankton author --cmd "run$i" --in "in$i" --out "o$i" --sign k.key --add >/dev/null 2>&1
  done
  cursor=$(plankton records --json 2>/dev/null | jq -r '.max // 0')
  # One more record is authored afterwards. It is unambiguously newer than the cursor.
  printf 'late-%s' "$round" > late; printf 'lateout-%s' "$round" > lo
  id=$(plankton author --cmd late --in late --out lo --sign k.key --add --print-id 2>/dev/null | tail -1 | tr -d '[:space:]')
  [ -n "$id" ] || id=$(plankton records --json 2>/dev/null | jq -r '.records[-1].fotonId // empty')
  # The peer asks for everything above its cursor. The new record must be in the answer.
  got=$(plankton records --json --since "$cursor" 2>/dev/null | jq -r --arg id "$id" '[.records[]?|select(.fotonId==$id)]|length')
  [ "${got:-0}" -ge 1 ] || { missed=$((missed+1)); echo "round $round: record $id added after cursor $cursor was NOT returned by --since $cursor"; }
done

echo "plankton: rounds where a post-sync record was withheld: $missed of $ROUNDS (expected 0)"

# The same defect in the other kernel, reached differently. nekton's format-2 subnektons are
# APPEND-ordered JSONL, so within one scope the numbering happened to be stable already - the
# unscoped case cannot show this. Across scopes it cannot: the store sorts objects/scope/<id>.jsonl
# by SCOPE ID, so a new scope whose id sorts before an existing one takes position 1 and pushes
# every record of the older scope up by one. The peer then re-receives what it already had and
# never sees the new scope at all. A scope id is a hash of a seed the attacker writes, so it is
# grindable: measured at ~2 attempts (1, 4 across runs).
if command -v nekton >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  N="$W/nk"; mkdir -p "$N"; export NEKTON_DIR="$N"
  ( cd "$N" && nekton keygen k >/dev/null 2>&1 )
  a=$( cd "$N" && nekton seed scopeA --sign k.key --add --print-id 2>/dev/null | tail -1 | tr -d '[:space:]' )
  cur=$( cd "$N" && nekton records --json 2>/dev/null | jq -r '.max // 0' )
  b=""; tries=0
  for n in $(seq 1 60); do
    cand=$( cd "$N" && nekton seed "scopeB$n" --sign k.key --add --print-id 2>/dev/null | tail -1 | tr -d '[:space:]' )
    [ -n "$cand" ] || continue
    tries=$n
    if [[ "${cand#sha256:}" < "${a#sha256:}" ]]; then b="$cand"; break; fi
    rm -f "$N/objects/scope/${cand#sha256:}.nekton.jsonl"   # discard: only an EARLIER-sorting scope is the attack
  done
  if [ -z "$b" ]; then
    # Never silently pass on a precondition we failed to build - that is the defect this whole
    # suite keeps finding in its own checks.
    echo "nekton: could not grind a scope id below $a in 60 attempts - PoC INCONCLUSIVE"
    missed=$((missed+1))
  else
    got=$( cd "$N" && nekton records --json --since "$cur" 2>/dev/null | jq -r --arg b "$b" '[.records[]?|select(.claimId==$b)]|length' )
    echo "nekton: scope $b sorts before $a (found in $tries attempts); returned above cursor $cur: ${got:-0} (expected 1)"
    [ "${got:-0}" -ge 1 ] || missed=$((missed+1))
  fi
else
  echo "nekton: nekton or jq not on PATH - plankton half only"
fi

if [ "$missed" -eq 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
