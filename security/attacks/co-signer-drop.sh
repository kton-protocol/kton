#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; nekton keygen a>/dev/null 2>&1; nekton keygen b>/dev/null 2>&1
printf '{"subject":[{"hash":"sha256:1111"}],"predicate":"https://kton.dev/v/note","object":{"x":"1"},"by":"a","when":"2026-07-16T00:00:00Z"}'>c.json
NEKTON_DIR=rA nekton claim c.json a.key --add>/dev/null 2>&1; NEKTON_DIR=rB nekton claim c.json b.key --add>/dev/null 2>&1
NEKTON_DIR=m nekton mirror rA>/dev/null 2>&1; NEKTON_DIR=m nekton mirror rB>/dev/null 2>&1
n=$(jq '.envelope.signatures|length' m/objects/sha256/*.json 2>/dev/null||echo 0)
[ "${n:-0}" -ge 2 ] && echo "VERDICT: PREVENTED" || echo "VERDICT: VULNERABLE"
