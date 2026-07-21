#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export NEKTON_DIR="$W/nd"; nekton keygen k>/dev/null 2>&1
printf '{"subject":[{"hash":"sha256:1"}],"predicate":"https://kton.dev/v/note","object":{"x":1},"by":"k","when":"whenever-you-like"}'>c.json
if nekton claim c.json k.key --add>/dev/null 2>&1; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
