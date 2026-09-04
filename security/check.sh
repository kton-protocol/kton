#!/usr/bin/env bash
# security/check.sh - the security regression gate. Runs the executable attack PoCs against the
# plankton/nekton/kton binaries on PATH. Optional $1 = a kton-examples checkout.
#
# Two lists, because they mean different things:
#   GATED - findings recorded as FIXED. Anything but PREVENTED is a regression and fails CI.
#   OPEN  - findings recorded as still open. They run and report, and do NOT fail the build;
#           the point is that they are visible and executable rather than described in prose.
#           A PREVENTED here is good news: move that id into GATED in the same commit.
#
# Verdicts a PoC may print: PREVENTED (the fix holds), VULNERABLE (it does not), N-A (the attack
# does not apply in this environment - no binary, no jq), INCONCLUSIVE (the PoC could not build the
# precondition it needs, so it proves nothing and MUST NOT read as a pass).
#
# The gate deliberately reports its own coverage. Most recorded attacks have no executable
# reproduction (they are prose in REPORT.md), and a gate that hides that ratio invites the
# reading that a green line means more than it does.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; KX="${1:-}"

GATED="suppress-replay corrupt-poisons-read co-signer-drop when-unvalidated silent-source-drop export-attribution canon-bigint rdf-injection spectrum-existence concurrency-races scope-path-traversal read-path-ungated union-across-payloads cursor-shift"
# envtally-CF2 is here, not in GATED, and deliberately: its path to the shipped release gate was
# wrong, so it never ran; with that fixed the gate runs but ticks NONE of its seven conditions in
# this scenario, which makes "env-qualified stayed unticked" meaningless. It now says INCONCLUSIVE
# instead of NOT VULNERABLE. Promoting it needs a 3/3 control run in which env-qualified DOES light.
OPEN="envtally-CF2"
SKIPPED=""

if [ -n "$KX" ] && [ -f "$KX/viewer/build_union.py" ]; then
  GATED="$GATED screenshot-viewer-labels"
else
  SKIPPED="screenshot-viewer-labels"
fi

run_one() {  # <id> -> echoes the verdict word
  bash "$HERE/attacks/$1.sh" "$KX" 2>/dev/null \
    | grep -oE 'VERDICT: (PREVENTED|VULNERABLE|N-A|INCONCLUSIVE)' | tail -1 | sed 's/^VERDICT: //'
}

fail=0
printf '%-26s %-12s %s\n' "attack" "verdict" "meaning"
printf '%-26s %-12s %s\n' "------" "-------" "-------"

for a in $GATED; do
  v=$(run_one "$a"); v=${v:-NO-VERDICT}
  case "$v" in
    PREVENTED)    note="fix holds" ;;
    N-A)          note="not applicable here" ;;
    # A PoC that could not build its own precondition proves NOTHING. It must not read as a pass -
    # that is how a check ends up unable to fail, which is a defect this suite has now found in
    # itself five times.
    INCONCLUSIVE) note="PoC COULD NOT RUN - proves nothing"; fail=1 ;;
    *)            note="REGRESSION"; fail=1 ;;
  esac
  printf '%-26s %-12s %s\n' "$a" "$v" "$note"
done

for a in $OPEN; do
  v=$(run_one "$a"); v=${v:-NO-VERDICT}
  case "$v" in
    PREVENTED)  note="now fixed - promote to GATED" ;;
    VULNERABLE) note="known open, not gated" ;;
    # In this list nothing reads as a pass to begin with - the finding is recorded as OPEN - so a
    # PoC saying it cannot decide is accurate reporting, not a silent failure. It does not fail CI;
    # what it does is stay visible until someone gives it the control it is missing.
    INCONCLUSIVE) note="known open, PoC cannot decide yet - needs a positive control" ;;
    N-A)        note="known open, does not apply here" ;;
    *)          note="known open, PoC did not run"; fail=1 ;;
  esac
  printf '%-26s %-12s %s\n' "$a" "$v" "$note"
done

for a in $SKIPPED; do
  printf '%-26s %-12s %s\n' "$a" "SKIPPED" "needs a kton-examples checkout (pass it as \$1)"
done

# Coverage: how much of the recorded engagement this gate actually executes.
total=$(ls "$HERE"/attacks/*.sh 2>/dev/null | grep -vc '/_' || echo 0)
exec_n=$(grep -l 'VERDICT' "$HERE"/attacks/*.sh 2>/dev/null | grep -vc '/_' || echo 0)
run_n=$(( $(printf '%s\n' $GATED | grep -c .) + $(printf '%s\n' $OPEN | grep -c .) ))

echo
echo "coverage: $run_n of $total recorded attacks run here; $exec_n have an executable VERDICT."
echo "          the remainder are documented in REPORT.md or run in the kton-examples CI - a"
echo "          green gate below means those $run_n held, not that the suite is complete."
echo
# The gate is only worth its green line if its proofs can fail. self-check.sh runs every PoC against
# binaries that do nothing; any that still says PREVENTED is not evidence.
echo
if ! bash "$HERE/self-check.sh" >/dev/null 2>&1; then
  echo "::error::a PoC in this gate passes against a binary that does nothing - run security/self-check.sh"
  fail=1
else
  echo "self-check: PASS - every PoC above can actually fail (security/self-check.sh)"
fi
echo

if [ "$fail" = 0 ]; then
  echo "SECURITY GATE: PASS - every finding recorded as fixed is still PREVENTED"
else
  echo "::error::SECURITY REGRESSION - a finding recorded as fixed is exploitable again, or an open PoC failed to run"
fi
exit $fail
