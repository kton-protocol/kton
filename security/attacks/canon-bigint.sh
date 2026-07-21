#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export NEKTON_DIR="$W/nd"; nekton keygen k>/dev/null 2>&1
printf '{"subject":[{"hash":"sha256:1111"}],"predicate":"https://kton.dev/v/note","object":{"n":9007199254740993},"by":"k","when":"2026-07-16T00:00:00Z"}'>c.json
if nekton claim c.json k.key --add>/dev/null 2>&1; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
