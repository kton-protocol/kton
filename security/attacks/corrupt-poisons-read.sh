#!/usr/bin/env bash
# corrupt-poisons-read: one unparseable file in objects/ must not disable reads over every OTHER
# record. A single bad byte would otherwise be a registry-wide denial of service.
#
# The decision is made on a COUNT from --json, not on a grep of the human output. The previous
# version asked `plankton uses <hash> | grep -q sha256`, and the miss message is
# "(none) - sha256:... is a lineage root or unknown in this registry" - which contains `sha256`.
# It therefore matched whether the read survived or not, and had reported PREVENTED since the day
# it was written. That is the exact defect this attack is about, committed by its own proof.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
command -v jq       >/dev/null 2>&1 || { echo "VERDICT: N-A (no jq)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A (no temp dir)"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/S"; mkdir -p S

plankton keygen k >/dev/null 2>&1
printf 'in\n' > f; printf 'out\n' > o
plankton author --cmd c --in f --out o --sign k.key --add >/dev/null 2>&1

# POSITIVE CONTROL: the good record must be readable BEFORE the corrupt file exists. Without this,
# a PoC that never managed to author anything reports "nothing broke" and passes.
before=$(plankton records --json 2>/dev/null | jq -r '.records|length')
if [ "${before:-0}" -lt 1 ]; then
  echo "setup failed: the registry holds ${before:-0} records before the attack - nothing to poison"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

printf 'garbage{{{' > S/objects/sha256/00bad.json

after=$(plankton records --json 2>/dev/null | jq -r '.records|length')
echo "records readable before the corrupt file: $before; after: ${after:-0} (expected $before)"
if [ "${after:-0}" -ge "$before" ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
