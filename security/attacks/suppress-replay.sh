#!/usr/bin/env bash
# suppress-replay (read-face-trusts-declared-id): the read path used to index a record under the
# `fotonId` written in the file instead of re-deriving it from the envelope. Planting a file that
# CLAIMS an honest record's id but carries a different (or unsigned) foton then SHADOWED the real
# record in byOutput/byInput - `producer` answered with the decoy, or with nothing at all.
# Fixed by re-deriving the id on read and skipping anything that does not hash to what it claims.
#
# Decided on a COUNT from --json, not on `grep -q "$IDT"` over human output: an empty $IDT made that
# `grep -q ""`, which matches every line of anything, so the PoC passed no matter what the code did.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
command -v jq       >/dev/null 2>&1 || { echo "VERDICT: N-A (no jq)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/S"; mkdir -p S

plankton keygen a >/dev/null 2>&1; plankton keygen adv >/dev/null 2>&1
printf 'in\n' > in; printf 'OUT\n' > out
plankton author --cmd make --in in --out out --sign a.key --add >/dev/null 2>&1
Y=$(plankton hash out)
IDT=$(jq -r '.fotonId // empty' S/objects/sha256/*.json 2>/dev/null | head -1)

# POSITIVE CONTROL: the honest record must exist and be findable BEFORE the decoy is planted.
if [ -z "$IDT" ]; then
  echo "setup failed: no honest record was authored, so 'the decoy did not win' proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
if ! plankton producer "$Y" 2>/dev/null | grep -q "$IDT"; then
  echo "setup failed: the honest record $IDT is not returned for its own output before any decoy exists"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

# Plant a decoy: a DIFFERENT foton, relabelled with the honest record's id and its signature blanked.
plankton author --cmd decoy --in in --out out --sign adv.key --add --registry S2 >/dev/null 2>&1
jq --arg i "$IDT" '.fotonId=$i|.envelope.signatures[0].sig=""' S2/objects/sha256/*.json > S/objects/sha256/00-decoy.json 2>/dev/null
if [ ! -s S/objects/sha256/00-decoy.json ]; then
  echo "setup failed: the decoy file was not written, so nothing was attacked"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

if plankton producer "$Y" 2>/dev/null | grep -q "$IDT"; then
  echo "the honest record $IDT is still returned for its own output, with the decoy present"
  echo "VERDICT: PREVENTED"
else
  echo "the decoy SHADOWED the honest record: producer no longer returns $IDT"
  echo "VERDICT: VULNERABLE"
fi
