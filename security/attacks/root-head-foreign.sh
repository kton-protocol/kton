#!/usr/bin/env bash
# root-head-foreign: a store's root chain is "the signed, ordered list of what this store said and
# opened" (SPEC §7.4) only if the entry it continues from is one it wrote itself. In #259 as first
# proposed, Add moved the local head whenever an accepted entry named the head as its prev - including
# an entry signed by ANY key and brought in by `nekton add` or mirror. The store owner's next own write
# then named the foreign entry as its prev: the owner's signature spliced a stranger's statement into
# the store's own chain, and `verify --root` counted a stranger's nk:registers as this store's.
#
# FIXED (#259 review R1, R3): the head moves only on the store's own writes; entries that name the root
# but arrive by add or mirror are reported off-chain and never counted.
set -u
for t in nekton python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
nekton keygen own >/dev/null 2>&1; nekton keygen stranger >/dev/null 2>&1
rootj() { NEKTON_DIR=A nekton verify --root --json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('$1'))" 2>/dev/null; }
spec() { printf '{"subject":[{"uri":"%s"}],"predicate":"https://kton.dev/v/x","by":"%s","when":"2026-11-19T10:00:0%sZ"%s}' "$1" "$2" "$3" "${4:-}"; }

nekton init --sign own.key --registry A >/dev/null 2>&1
spec urn:x:1 own 1 > s1.json; nekton claim s1.json own.key --add --registry A >/dev/null 2>&1
R=$(rootj root); H=$(rootj head)
case "$R$H" in sha256:*sha256:*) ;; *) echo "setup failed: no root chain (root=$R head=$H)"; echo "VERDICT: INCONCLUSIVE"; exit 0 ;; esac

# The stranger appends to the owner's root chain, and registers a subnekton in it.
spec urn:x:evil stranger 2 ",\"scope\":\"$R\",\"prev\":\"$H\"" > f.json
nekton claim f.json stranger.key f.dsse >/dev/null 2>&1
printf '{"subject":[{"hash":"sha256:%064d"}],"predicate":"https://kton.dev/v/registers","by":"stranger","when":"2026-11-19T10:00:03Z","scope":"%s","prev":"%s"}' 7 "$R" "$H" > g.json
nekton claim g.json stranger.key g.dsse >/dev/null 2>&1
[ -s f.dsse ] && [ -s g.dsse ] || { echo "setup failed: the stranger's entries were not signed"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
NEKTON_DIR=A nekton add f.dsse >/dev/null 2>&1; NEKTON_DIR=A nekton add g.dsse >/dev/null 2>&1
FID=$(NEKTON_DIR=A nekton show f.dsse 2>/dev/null | awk '/^claim:/{print $2}')

# The owner writes again. Which entry does it continue from?
spec urn:x:2 own 4 > s2.json
ID=$(nekton claim s2.json own.key --add --registry A --print-id 2>/dev/null)
PREV=$(python3 - A/objects "$ID" <<'PY'
import base64, glob, json, sys
for f in glob.glob(sys.argv[1] + "/**/*.nekton.jsonl", recursive=True):
    for line in open(f):
        r = json.loads(line)
        if r.get("claimId") == sys.argv[2]:
            print(json.loads(base64.b64decode(r["envelope"]["payload"]))["predicate"].get("prev", ""))
PY
)
REG=$(rootj registered)
[ -n "$FID" ] && [ -n "$PREV" ] || { echo "setup failed: could not read the entries back"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
spliced=0; [ "$PREV" = "$FID" ] && spliced=1
echo "owner's next write continues from the stranger's entry: $spliced (want 0); stranger's registers counted as this store's: $REG (want 0)"
if [ "$spliced" = 0 ] && [ "$REG" = 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
