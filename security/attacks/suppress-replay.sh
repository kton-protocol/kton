#!/usr/bin/env bash
# suppress-replay (read-face-trusts-declared-id): plant a collision-id decoy; producer must still return
# the honest record (fix: re-derive id on read). Uses plankton from PATH.
set -e; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/S"; mkdir -p S
plankton keygen a>/dev/null 2>&1; plankton keygen adv>/dev/null 2>&1; printf 'in\n'>in; printf 'OUT\n'>out
plankton author --cmd make --in in --out out --sign a.key --add>/dev/null 2>&1
Y=$(plankton hash out); IDT=$(jq -r .fotonId S/objects/sha256/*.json)
plankton author --cmd decoy --in in --out out --sign adv.key --add --registry S2>/dev/null 2>&1
jq --arg i "$IDT" '.fotonId=$i|.envelope.signatures[0].sig=""' S2/objects/sha256/*.json > S/objects/sha256/00-decoy.json
if plankton producer "$Y" 2>/dev/null | grep -q "$IDT"; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
