#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/pd"
plankton keygen att>/dev/null 2>&1; plankton keygen vic>/dev/null 2>&1; printf 'd\n'>d; printf 'm\n'>m
plankton author --in d --out m --cmd t --sign att.key -o real.json>/dev/null 2>&1
VK=$(plankton author --in d --out m --cmd x --sign vic.key -o v.json>/dev/null 2>&1; jq -r '.signatures[0].keyid' v.json)
jq --arg k "$VK" '.signatures[0].keyid=$k' real.json>framed.json; plankton add framed.json>/dev/null 2>&1
if plankton export --rdf 2>/dev/null | grep -q wasAttributedTo; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
