#!/usr/bin/env bash
# export-attribution: an envelope's `keyid` is a self-declared HINT - it is not covered by the
# signature (SPEC §8). Re-label an attacker's record with a victim's keyid and the RDF export used
# to emit `prov:wasAttributedTo <victim>`, turning an unverified hint into a published statement
# about who did the work. Fixed by exporting attribution only for a signature that VERIFIES.
#
# The decision greps for a string that must be ABSENT, so an export that produces NOTHING - a
# renamed flag, a swallowed error, a binary that does not run - used to read as PREVENTED. It now
# proves the export works and names the record first.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
command -v jq       >/dev/null 2>&1 || { echo "VERDICT: N-A (no jq)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/pd"

plankton keygen att >/dev/null 2>&1; plankton keygen vic >/dev/null 2>&1
printf 'd\n' > d; printf 'm\n' > m
plankton author --in d --out m --cmd t --sign att.key -o real.json >/dev/null 2>&1
plankton author --in d --out m --cmd x --sign vic.key -o v.json  >/dev/null 2>&1
VK=$(jq -r '.signatures[0].keyid // empty' v.json 2>/dev/null)
if [ -z "$VK" ]; then
  echo "setup failed: could not read the victim's keyid, so there is no false attribution to look for"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
# Relabel the attacker's record with the victim's keyid. The signature is untouched and does NOT
# verify under that key - which is the whole point.
jq --arg k "$VK" '.signatures[0].keyid=$k' real.json > framed.json
plankton add framed.json >/dev/null 2>&1

rdf=$(plankton export --rdf 2>/dev/null)
# POSITIVE CONTROL: the export must actually have exported this record. An empty export trivially
# contains no wasAttributedTo.
if [ "$(printf '%s' "$rdf" | grep -c .)" -lt 1 ] || ! printf '%s' "$rdf" | grep -q 'kton.dev\|sha256'; then
  echo "setup failed: 'plankton export --rdf' produced no statements about the record"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

n=$(printf '%s' "$rdf" | grep -c wasAttributedTo)
echo "export names $(printf '%s' "$rdf" | grep -c .) statements; prov:wasAttributedTo among them: $n (expected 0)"
if [ "$n" -eq 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
