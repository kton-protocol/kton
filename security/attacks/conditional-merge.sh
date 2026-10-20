#!/usr/bin/env bash
# conditional-merge: a step that read a database is reproducible only under conditions (#212), and
# the mark is what keeps `reuse` from handing a stale database answer out as the result of a pure
# function. A kernel that drops the mark merges the conditional record into its unconditional twin:
# same foton id, same action key, a cache HIT. The deployed v0 kernels did exactly that - protocol
# was decoded with a plain json.Unmarshal, and an unknown `conditions` member vanished.
#
# FIXED: `conditions` is covered (its own action key) and admissible only on foton/v1, whose payload
# must be byte-identical to the canonical statement; a foton/v0 statement carrying it is refused.
#
# The v0 variant is signed outside plankton (openssl, Ed25519), so a positive control first proves
# that this signing path produces an envelope the registry accepts.
set -u
for t in plankton jq openssl python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
printf 'select *' > q.sql; printf rows > snap.csv
for k in a tool; do plankton keygen "$k" >/dev/null 2>&1; done

sign_raw() {
  python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))' \
    <<<"302e020100300506032b657004220420$(cat "$1")" > k.der
  openssl pkey -inform DER -in k.der -out k.pem 2>/dev/null || return 1
  pt=application/vnd.in-toto+json
  { printf 'DSSEv1 %s %s %s ' "${#pt}" "$pt" "$(wc -c < "$2" | tr -d ' ')"; cat "$2"; } > pae.bin
  openssl pkeyutl -sign -inkey k.pem -rawin -in pae.bin -out sig.bin 2>/dev/null || return 1
  jq -n --arg p "$(base64 -w0 < "$2")" --arg s "$(base64 -w0 < sig.bin)" --arg pt "$pt" \
    '{payloadType:$pt, payload:$p, signatures:[{keyid:"", sig:$s}]}' > "$3"
}

plankton author --cmd "psql -f q.sql" --in q.sql --out snap.csv --sign a.key -o v0.dsse >/dev/null 2>&1
jq -r .payload v0.dsse | base64 -d > v0.json 2>/dev/null
[ -s v0.json ] || { echo "setup failed: no v0 record authored"; echo "VERDICT: INCONCLUSIVE"; exit 0; }

# POSITIVE CONTROL: the honest v0 bytes, signed this way, are admitted.
sign_raw tool.key v0.json ctl.dsse || { echo "VERDICT: N-A (openssl cannot sign Ed25519 here)"; exit 0; }
if ! PLANKTON_DIR="$W/ctl" plankton add ctl.dsse >/dev/null 2>&1; then
  echo "setup failed: a v0 payload signed outside plankton was refused, so a refusal proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

# 1. The same v0 statement with protocol.conditions: must be refused, not merged.
python3 -c 'import json,sys
st=json.load(open(sys.argv[1])); st["predicate"]["protocol"]["conditions"]=[{"kind":"database","ref":"prod"}]
sys.stdout.write(json.dumps(st,separators=(",",":"),sort_keys=True))' v0.json > v0c.json
sign_raw tool.key v0c.json v0c.dsse || { echo "VERDICT: INCONCLUSIVE"; exit 0; }
export PLANKTON_DIR="$W/reg"
plankton add v0.dsse >/dev/null 2>&1
if plankton add v0c.dsse >/dev/null 2>&1; then v0merged=1; else v0merged=0; fi

if [ "$v0merged" = 1 ]; then
  echo "a foton/v0 statement carrying protocol.conditions was admitted: it is the unconditional record with the mark dropped"
  echo "VERDICT: VULNERABLE"; exit 0
fi

# 2. On v1 the conditional record is its own computation: a different action key, and the
#    unconditional computation's reuse (the v0 and v1 records of it share one key) finds no
#    conditional hit.
plankton author --statement v1 --cmd "psql -f q.sql" --in q.sql --out snap.csv --sign a.key -o plain.dsse --add >/dev/null 2>&1
plankton author --statement v1 --cmd "psql -f q.sql" --in q.sql --out snap.csv --condition database=prod \
  --sign a.key -o cond.dsse --add >/dev/null 2>&1
[ -s cond.dsse ] || { echo "setup failed: no conditional v1 record authored"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
akp=$(plankton reuse plain.dsse --json 2>/dev/null | jq -r .actionKey)
akc=$(plankton reuse cond.dsse --json 2>/dev/null | jq -r .actionKey)
leaked=$(plankton reuse plain.dsse --json 2>/dev/null | jq '[.hits[] | select(.conditions)] | length')
marked=$(plankton reuse cond.dsse --json 2>/dev/null | jq '[.hits[] | select(.conditions)] | length')
same=0; [ "$akp" = "$akc" ] && same=1
echo "v0 + conditions admitted: 0 (want 0); v1 action keys equal: $same (want 0); conditional hits for the plain computation: ${leaked:-?} (want 0); conditional hit marked: ${marked:-?} (want 1)"
if [ "$same" = 0 ] && [ "${leaked:-1}" = 0 ] && [ "${marked:-0}" = 1 ]; then
  echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
