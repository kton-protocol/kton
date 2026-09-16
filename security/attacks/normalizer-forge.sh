#!/usr/bin/env bash
SD="$(cd "$(dirname "$0")" && pwd)"; . "$SD/_records.sh"
# normalizer-forge - a DEMONSTRATION, not an attack, and it deliberately prints no VERDICT.
#
# Two `--kind normalize` fotons that both declare the same output C make `reproduces --via` report L1
# for genuinely different A and B. That is BY DESIGN: plankton documents, it never executes, so it can
# only believe what a signed foton says it produced. There is nothing here for the kernel to prevent.
#
# The FINDING was that a release gate used `--via` as if it were a re-verification. It is fixed in
# example 12's Act 8a by RE-EXECUTING the normalizer rather than trusting the edge, and that is where
# the assertable property lives - not here. A PREVENTED/VULNERABLE verdict would be a category error:
# this script shows a primitive working as specified.
#
# Two things about how it is invoked, both of which have cost someone time:
#
#   - it used to take the BINARY PATH as $1, while every other PoC in this directory takes a
#     kton-examples checkout there. Calling it the way the rest of the suite is called ran the wrong
#     thing. It now uses `plankton` from PATH like everything else, and ignores its arguments.
#   - it used to glob pd/objects/sha256/*.json directly, which is exactly what _records.sh exists to
#     stop: a layout change turns a working PoC into a fake regression. It reads through the helper now.
set -uo pipefail
command -v plankton >/dev/null 2>&1 || { echo "no plankton on PATH - nothing to demonstrate"; exit 0; }
command -v python3  >/dev/null 2>&1 || { echo "no python3 - nothing to demonstrate"; exit 0; }
W=$(mktemp -d) || exit 0
cd "$W" || exit 0
export PLANKTON_DIR="$W/pd"
plankton keygen k >/dev/null 2>&1
printf 'A OBJ=-5.56\n' > A; printf 'B OBJ=-9.99\n' > B; printf 'CANON\n' > C
plankton author --cmd n --kind normalize --in A --out C --sign k.key --add >/dev/null 2>&1
plankton author --cmd n --kind normalize --in B --out C --sign k.key --add >/dev/null 2>&1

POT=$(plankton records --json 2>/dev/null | python3 -c '
import json,sys,base64
d=json.load(sys.stdin)
for r in d.get("records",[]):
    st=json.loads(base64.b64decode(r["envelope"]["payload"]))
    p=st["predicate"]["protocol"]
    if p.get("kind")=="normalize":
        print(p["ref"]); break')
if [ -z "$POT" ]; then
  echo "could not find the normalize foton - the demonstration did not run"
  exit 0
fi
echo "two normalize fotons, different inputs (A, B), both declaring output C"
echo -n "reproduces A B --via <that normalizer>: "
plankton reproduces "$(plankton hash A)" "$(plankton hash B)" --via "$POT" 2>&1 | head -1
echo
echo "This is the specified behaviour: plankton records what a signed foton CLAIMS it produced and"
echo "never executes it. A gate that treats --via as re-verification is the defect; example 12's"
echo "Act 8a re-executes the normalizer instead, which is where that property is tested."
