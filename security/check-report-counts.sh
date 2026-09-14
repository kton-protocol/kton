#!/usr/bin/env bash
# security/check-report-counts.sh - REPORT.md states counts about this directory. This recomputes
# them and fails if the prose and the directory disagree.
#
# Why this exists: REPORT.md shipped a posture of "27/29 spectrum members fulfilled · 27 closed ·
# 2 open" over a Closed table with 24 rows, and "10 of the 28 PoCs are executable" when 17 were and
# check.sh ran 16. Four gated PoCs had no row at all. None of it was caught, because a number in
# prose is maintained by whoever remembers to - which is the same defect the suite keeps finding in
# the code it attacks: a claim nothing can falsify.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R="$HERE/REPORT.md"
fail=0
say() { printf '  %-34s stated %-4s actual %-4s %s\n' "$1" "$2" "$3" "$4"; }
cmp_n() {  # <label> <stated> <actual>
  if [ "$2" = "$3" ]; then say "$1" "$2" "$3" "ok"; else say "$1" "$2" "$3" "MISMATCH"; fail=1; fi
}

# --- actual, from the directory and the gate itself ---
a_total=$(ls "$HERE"/attacks/*.sh 2>/dev/null | grep -vc '/_')
a_exec=$(grep -lE '(echo|printf)[^|#]*VERDICT: ' "$HERE"/attacks/*.sh 2>/dev/null | grep -vc '/_')
a_closed=$(awk '/^## Closed/,/^## Open/'     "$R" | grep -cE '^\| `')
a_open=$(awk   '/^## Open/,/^## Accepted/'   "$R" | grep -cE '^\| `')
a_bound=$(awk  '/^## Accepted/,/^## Detail/' "$R" | grep -cE '^- \*\*`')
# what check.sh actually runs = its two lists
a_run=$(grep -E '^(GATED|OPEN)=' "$HERE/check.sh" | sed 's/^[A-Z]*="//;s/"$//' | tr ' ' '\n' | grep -c .)

# --- stated, from REPORT.md's posture block ---
posture=$(grep -m1 '^## Posture:' "$R")
s_closed=$(echo "$posture" | grep -oE '[0-9]+ closed'   | grep -oE '[0-9]+')
s_open=$(echo   "$posture" | grep -oE '[0-9]+ open'     | grep -oE '[0-9]+')
s_bound=$(echo  "$posture" | grep -oE '[0-9]+ accepted' | grep -oE '[0-9]+')
s_total=$(echo  "$posture" | grep -oE 'of [0-9]+ recorded' | grep -oE '[0-9]+')
cov=$(grep -m1 -E '^\*\*[0-9]+ of the [0-9]+ PoCs are executable\*\*' "$R")
s_exec=$(echo "$cov" | sed -E 's/^\*\*([0-9]+) of the ([0-9]+).*/\1/')
s_exec_total=$(echo "$cov" | sed -E 's/^\*\*([0-9]+) of the ([0-9]+).*/\2/')
s_run=$(echo "$cov" | grep -oE 'runs \*\*[0-9]+\*\*' | grep -oE '[0-9]+')

for v in s_closed s_open s_bound s_total s_exec s_exec_total s_run; do
  [ -n "${!v}" ] || { echo "::error::REPORT.md posture block no longer parses ($v not found) - the guard cannot check it"; exit 1; }
done

echo "REPORT.md vs this directory:"
cmp_n "attacks recorded"          "$s_total"      "$a_total"
cmp_n "  closed"                  "$s_closed"     "$a_closed"
cmp_n "  open"                    "$s_open"       "$a_open"
cmp_n "  accepted boundary"       "$s_bound"      "$a_bound"
cmp_n "PoCs that are executable"  "$s_exec"       "$a_exec"
cmp_n "  out of"                  "$s_exec_total" "$a_total"
cmp_n "PoCs check.sh runs"        "$s_run"        "$a_run"

sum=$((a_closed + a_open + a_bound))
if [ "$sum" != "$a_total" ]; then
  echo "::error::the tables account for $sum attacks but $a_total scripts are on disk - one is unrecorded"
  fail=1
fi

[ "$fail" = 0 ] && echo "report counts: PASS" || echo "::error::REPORT.md states counts this directory does not support"
exit $fail
