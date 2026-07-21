#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/pd"; mkdir -p pd
H="sha256:$(printf 'ff%.0s' {1..32})"
plankton spectrum define --id x --member m=$H -o s.json>/dev/null 2>&1
if plankton spectrum check s.json --candidate m=$H>/dev/null 2>&1; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
