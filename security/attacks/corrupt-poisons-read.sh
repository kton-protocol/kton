#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/S"; mkdir -p S
plankton keygen k>/dev/null 2>&1; printf x>f; plankton author --cmd c --in f --out f --sign k.key --add>/dev/null 2>&1
printf 'garbage{{{'>S/objects/sha256/00bad.json
if plankton uses "$(plankton hash f)" 2>/dev/null | grep -q sha256; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
