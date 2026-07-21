#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/S"; mkdir -p S
plankton keygen k>/dev/null 2>&1; printf x>f; plankton author --cmd c --in f --out f --sign k.key --add>/dev/null 2>&1
if plankton uses --source S --source "/tmp/NOPE-$$" "$(plankton hash f)">/dev/null 2>&1; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
