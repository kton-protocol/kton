#!/usr/bin/env bash
# normalizer-forge PRIMITIVE: two --kind normalize fotons both --out C make `reproduces --via` report
# L1 for genuinely-different A/B. This is BY DESIGN (plankton never executes); the FINDING is that a gate
# used it as a re-verification (fixed in ex-12 Act-8a by RE-EXECUTING the normalizer).
set -e; PB="${1:-plankton}"; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/pd"
"$PB" keygen k >/dev/null 2>&1
printf 'A OBJ=-5.56\n'>A; printf 'B OBJ=-9.99\n'>B; printf 'CANON\n'>C
"$PB" author --cmd n --kind normalize --in A --out C --sign k.key --add >/dev/null 2>&1
"$PB" author --cmd n --kind normalize --in B --out C --sign k.key --add >/dev/null 2>&1
POT=$(python3 -c "import json,base64,glob
for f in glob.glob('pd/objects/sha256/*.json'):
 s=json.loads(base64.b64decode(json.load(open(f))['envelope']['payload']))
 if s['predicate']['protocol'].get('kind')=='normalize': print(s['predicate']['protocol']['ref']); break")
echo -n "reproduces A B --via POT: "; "$PB" reproduces "$("$PB" hash A)" "$("$PB" hash B)" --via "$POT" 2>&1
