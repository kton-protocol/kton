#!/usr/bin/env bash
# security/self-check.sh - does the security gate's own proof actually prove anything?
#
# Every attack PoC asserts something about a binary's behaviour, and most of them assert that
# something did NOT happen: no file outside the store, no forged attribution, no lost signature. A
# PoC written that way passes trivially against a binary that never does anything - and this
# repository has now found that defect in itself five times, once inside the proof of the very
# attack about a check that could not fail.
#
# So each PoC is run against stub binaries, in two modes, because they catch different mistakes:
#
#   dead   - exists, exits 1, says nothing. Catches a PoC whose passing verdict is its INITIAL
#            state, only ever revised downward (concurrency-races: `worst=3`, and an empty count
#            made the comparison error out instead of lowering it), and one that asserts a file the
#            SCRIPT itself wrote is unchanged (scope-path-traversal).
#   quiet  - exists, exits 0, says nothing. Catches a PoC that greps for a string which must be
#            ABSENT: an export that emits nothing contains no forged attribution either
#            (rdf-injection).
#
# In both modes the honest answers are VULNERABLE, N-A and INCONCLUSIVE. PREVENTED is not one:
# nothing was prevented, because nothing ran.
#
# WHAT THIS DOES NOT CATCH, stated plainly so the green line is not read as more than it is.
# Measured against the five defective PoCs this was written for: it flags concurrency-races,
# scope-path-traversal and rdf-injection, and MISSES two.
#
#   corrupt-poisons-read  greps real output for a needle the negative answer also contains -
#                         `grep -q sha256` against a miss message reading "(none) - sha256:... is a
#                         lineage root or unknown in this registry". No stub can reproduce that: the
#                         defect lives in the WORKING binary's prose.
#   export-attribution    ran under `set -e`, so a stubbed `keygen` killed it before its predicate
#                         was ever reached. NO-VERDICT is honest, but it is not detection.
#
# The rule that covers both is a review rule, not a script: decide on a COUNT from --json, never on
# a grep of a sentence, and never let `set -e` stand in for a precondition check.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STUB="$(mktemp -d)" || { echo "cannot create a temp dir"; exit 1; }
trap 'rm -rf "$STUB"' EXIT
mkdir -p "$STUB/dead" "$STUB/quiet"
for b in plankton nekton kton; do
  printf '#!/bin/sh\nexit 1\n' > "$STUB/dead/$b";  chmod +x "$STUB/dead/$b"
  printf '#!/bin/sh\nexit 0\n' > "$STUB/quiet/$b"; chmod +x "$STUB/quiet/$b"
done

verdict() { # <mode> <script>
  PATH="$STUB/$1:/usr/bin:/bin" timeout 120 bash "$2" 2>/dev/null \
    | grep -oE 'VERDICT: [A-Z-]+' | tail -1 | sed 's/^VERDICT: //'
}

fail=0
printf '%-26s %-14s %-14s %s\n' "attack" "dead binary" "quiet binary" "meaning"
printf '%-26s %-14s %-14s %s\n' "------" "-----------" "------------" "-------"
for f in "$HERE"/attacks/*.sh; do
  a=$(basename "$f" .sh); case "$a" in _*) continue ;; esac
  grep -q 'VERDICT' "$f" || continue   # prose-only reproductions have nothing to self-check
  d=$(verdict dead "$f"); q=$(verdict quiet "$f")
  if [ "${d:-}" = PREVENTED ] || [ "${q:-}" = PREVENTED ]; then
    note="CANNOT FAIL - passes against a binary that does nothing"; fail=1
  else
    note="honest"
  fi
  printf '%-26s %-14s %-14s %s\n' "$a" "${d:-NO-VERDICT}" "${q:-NO-VERDICT}" "$note"
done

echo
if [ "$fail" = 0 ]; then
  echo "SELF-CHECK: PASS - no PoC reports PREVENTED against a binary that does nothing"
else
  echo "::error::SELF-CHECK FAILED - a PoC passes without the code under test doing anything."
  echo "::error::Give it a POSITIVE CONTROL: assert the precondition actually holds (the record was"
  echo "::error::authored, the export produced output, a benign twin was accepted) and print"
  echo "::error::VERDICT: INCONCLUSIVE when it does not."
fi
exit $fail
