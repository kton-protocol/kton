#!/usr/bin/env bash
# The repository states its scope TWICE, on purpose and for different readers:
#
#   spec/SPEC.md §1                        what THIS DOCUMENT specifies (an ISO-style clause)
#   community-specification/02-scope.md    what the PATENT COMMITMENT covers (Community Spec License)
#
# They are not the same statement and should not be merged - but they must not disagree about which
# topics are in and out. They already did once: SPEC §1 gained the signed-PDF exclusion and the
# evidence-evaluation carve-out while 02-scope.md had neither, and it was found by reading rather
# than by a check (#66, synced by hand in #67). One of these two files defines what is
# patent-committed, so hand-syncing is not a strategy.
#
# Each scope item therefore carries an invisible key: <!-- scope:in KEY --> / <!-- scope:out KEY -->.
# The prose stays free; the KEY SETS must match. Adding an item to one file and not the other fails
# here rather than a year later in a licensing conversation.
set -uo pipefail
cd "$(dirname "$0")/.."
A=spec/SPEC.md
B=community-specification/02-scope.md

keys() { grep -o "<!-- scope:$2 [a-z0-9-]* -->" "$1" | awk '{print $3}' | sort -u; }

fail=0
for side in in out; do
  a=$(keys "$A" "$side"); b=$(keys "$B" "$side")
  only_a=$(comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b"))
  only_b=$(comm -13 <(printf '%s\n' "$a") <(printf '%s\n' "$b"))
  n=$(printf '%s\n' "$a" | grep -c . || true)
  printf '%-4s %2d keys\n' "$side" "$n"
  if [ -n "$only_a" ]; then
    echo "::error::scope drift - $side only in $A: $(echo $only_a)"; fail=1
  fi
  if [ -n "$only_b" ]; then
    echo "::error::scope drift - $side only in $B: $(echo $only_b)"; fail=1
  fi
done

# A scope item with no key is invisible to this check, which would make the check itself the kind of
# green-but-blind gate this project keeps finding. Assert both files carry some.
for f in "$A" "$B"; do
  if [ "$(grep -c '<!-- scope:' "$f")" -lt 5 ]; then
    echo "::error::$f carries fewer than 5 scope markers - a new item was probably added without one"; fail=1
  fi
done

if [ "$fail" = 0 ]; then
  echo "SCOPE: the two statements agree on what is in and out"
else
  echo "::error::the two scope statements disagree - one of them defines what is patent-committed"
fi
exit $fail
