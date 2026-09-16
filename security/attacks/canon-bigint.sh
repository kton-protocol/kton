#!/usr/bin/env bash
# canon-bigint: canonical JSON (SPEC §6) must round-trip a number exactly, or two implementations
# compute different ids for the same statement. An integer beyond 2^53 does not survive a float64,
# so it is refused at authoring rather than silently re-encoded.
#
# REFUSAL test, so it carries a benign twin: identical but for the number. The old version used
# "hash":"sha256:1111" - not a valid content hash - and so was refused before the number mattered.
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export NEKTON_DIR="$W/nd"
nekton keygen k >/dev/null 2>&1
H="sha256:abababababababababababababababababababababababababababababababab"

tmpl() { printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"n":%s},"by":"k","when":"2026-07-16T00:00:00Z"}' "$H" "$1"; }

tmpl 42 > ok.json
if ! nekton claim ok.json k.key --add >/dev/null 2>&1; then
  echo "setup failed: the BENIGN twin (same claim with n=42) was refused too, so refusing the"
  echo "out-of-range integer says nothing about number canonicalisation"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

tmpl 9007199254740993 > bad.json   # 2^53 + 1: not representable as a float64
if nekton claim bad.json k.key --add >/dev/null 2>&1; then
  echo "an integer past 2^53 was signed - its canonical form is not reproducible across implementations"
  echo "VERDICT: VULNERABLE"
else
  echo "n=42 accepted, n=2^53+1 refused - the check is selective"
  echo "VERDICT: PREVENTED"
fi
