#!/usr/bin/env bash
# union-across-payloads: a foton id covers inputs/outputs/protocol. `uri` is CARRIED, not covered
# (SPEC 6.1), so two honest producers can publish the same computation with different locators: same
# id, different signed bytes. The store kept the FIRST payload and unioned BOTH signature sets.
#
# A signature stands over PAE(payloadType, payload), so the second producer's signature then hung on
# bytes it never signed. Demonstrated: the stored record carried the attacker's locator, the
# signature list held both keyids, and `plankton verify` with the honest producer's key answered
# WRONG KEY - the honest producer presented as an endorser of someone else's payload, and
# `records --json` republished it to every peer.
#
# FIXED #93: never merge across differing bytes. One carried variant wins (order-dependent, and said
# so in the code), but no keyid is ever attached to bytes its owner did not sign.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/reg"
printf a > f.txt; printf b > o.txt
plankton keygen evil   >/dev/null 2>&1
plankton keygen honest >/dev/null 2>&1

plankton author --cmd run --in f.txt --out o.txt --located "o.txt=https://evil.example/pwned" \
  --sign evil.key   --add >/dev/null 2>&1
plankton author --cmd run --in f.txt --out o.txt --located "o.txt=https://honest.example/o" \
  --sign honest.key --add >/dev/null 2>&1

sigs=$(plankton records --json 2>/dev/null | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(len(d['records'][0]['envelope']['signatures']) if d['records'] else 0)" 2>/dev/null || echo 9)

# The decisive check: every signature on the stored record must actually verify against SOME key we
# hold. A count alone would pass if the code merged and the payloads happened to match.
bogus=0
for k in evil.pub honest.pub; do
  plankton verify "$(plankton records --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["records"][0]["fotonId"])')" "$k" >/dev/null 2>&1 && ok=$((${ok:-0}+1))
done
[ "${ok:-0}" -lt "$sigs" ] && bogus=1

echo "signatures on the stored record: $sigs (want 1);  signatures no key verifies: $bogus (want 0)"
if [ "$sigs" = 1 ] && [ "$bogus" = 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
