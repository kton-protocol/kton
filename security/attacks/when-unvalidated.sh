#!/usr/bin/env bash
# when-unvalidated: `when` is a signed timestamp that downstream consumers order and compare on.
# It used to be accepted as any string at all, so "whenever-you-like" was signed and stored, and a
# reader sorting by it had no way to tell. Fixed by requiring RFC 3339 at authoring.
#
# This is a REFUSAL test, and a refusal proves nothing on its own: the command might be failing for
# an unrelated reason. (It was - the old version used "hash":"sha256:1", which is not a valid
# content hash, so the claim was rejected before `when` was ever looked at.) The benign twin below
# differs ONLY in the `when` value and MUST be accepted.
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export NEKTON_DIR="$W/nd"
nekton keygen k >/dev/null 2>&1
H="sha256:abababababababababababababababababababababababababababababababab"

tmpl() { printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"x":1},"by":"k","when":"%s"}' "$H" "$1"; }

tmpl '2026-07-16T00:00:00Z' > ok.json
if ! nekton claim ok.json k.key --add >/dev/null 2>&1; then
  echo "setup failed: the BENIGN twin (identical but for a valid RFC 3339 `when`) was refused too,"
  echo "so a refusal of the hostile one says nothing about `when` validation"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

tmpl 'whenever-you-like' > bad.json
if nekton claim bad.json k.key --add >/dev/null 2>&1; then
  echo "a claim with when=\"whenever-you-like\" was signed and stored"
  echo "VERDICT: VULNERABLE"
else
  echo "benign `when` accepted, malformed `when` refused - the check is selective"
  echo "VERDICT: PREVENTED"
fi
