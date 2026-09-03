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
# The gate deliberately reports its own coverage. Most recorded attacks have no executable
# reproduction (they are prose in REPORT.md), and a gate that hides that ratio invites the
# reading that a green line means more than it does.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; KX="${1:-}"

GATED="suppress-replay corrupt-poisons-read co-signer-drop when-unvalidated silent-source-drop export-attribution canon-bigint rdf-injection spectrum-existence concurrency-races"
OPEN=""
SKIPPED=""

if [ -n "$KX" ] && [ -f "$KX/viewer/build_union.py" ]; then
  GATED="$GATED screenshot-viewer-labels"
else
  SKIPPED="screenshot-viewer-labels"
fi

run_one() {  # <id> -> echoes the verdict word
  bash "$HERE/attacks/$1.sh" "$KX" 2>/dev/null \
    | grep -oE 'VERDICT: (PREVENTED|VULNERABLE|N-A)' | tail -1 | sed 's/^VERDICT: //'
}

fail=0
printf '%-26s %-12s %s\n' "attack" "verdict" "meaning"
printf '%-26s %-12s %s\n' "------" "-------" "-------"

for a in $GATED; do
  v=$(run_one "$a"); v=${v:-NO-VERDICT}
  case "$v" in
    PREVENTED|N-A) note="fix holds" ;;
    *)             note="REGRESSION"; fail=1 ;;
  esac
  printf '%-26s %-12s %s\n' "$a" "$v" "$note"
done

for a in $OPEN; do
  v=$(run_one "$a"); v=${v:-NO-VERDICT}
  case "$v" in
    PREVENTED) note="now fixed - promote to GATED" ;;
    VULNERABLE) note="known open, not gated" ;;
    *)         note="known open, PoC did not run"; fail=1 ;;
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
if [ "$fail" = 0 ]; then
  echo "SECURITY GATE: PASS - every finding recorded as fixed is still PREVENTED"
else
  echo "::error::SECURITY REGRESSION - a finding recorded as fixed is exploitable again, or an open PoC failed to run"
fi
exit $fail
