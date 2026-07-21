#!/usr/bin/env bash
# security/check.sh - the security regression gate. Runs each attack (a signed foton + nekton finding in
# the kton-redteam provenance graph) against the plankton/nekton/kton binaries on PATH, and asserts every
# fixed finding is still PREVENTED. Exit non-zero on any regression. Optional $1 = a kton-examples checkout
# (enables the viewer attack). Theory + vulnerable/fixed commits: security/REPORT.md.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; KX="${1:-}"
GATED="suppress-replay corrupt-poisons-read co-signer-drop when-unvalidated silent-source-drop export-attribution canon-bigint rdf-injection spectrum-existence"
[ -n "$KX" ] && [ -f "$KX/viewer/build_union.py" ] && GATED="$GATED screenshot-viewer-labels"
fail=0
printf '%-26s %s\n' "attack (fixed finding)" "verdict"
printf '%-26s %s\n' "----------------------" "-------"
for a in $GATED; do
  v=$(bash "$HERE/attacks/$a.sh" "$KX" 2>/dev/null | grep -oE 'VERDICT: (PREVENTED|VULNERABLE|N-A)' | tail -1); v=${v#VERDICT: }
  printf '%-26s %s\n' "$a" "${v:-NO-VERDICT}"
  case "$v" in PREVENTED|N-A) ;; *) fail=1;; esac
done
echo
if [ "$fail" = 0 ]; then echo "SECURITY GATE: PASS - every fixed finding is still PREVENTED"
else echo "::error::SECURITY REGRESSION - a previously-fixed attack is exploitable again (VULNERABLE above)"; fi
exit $fail
