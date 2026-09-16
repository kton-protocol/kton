#!/usr/bin/env bash
# spectrum-existence: a spectrum's members are content hashes. `spectrum check` used to report a
# member FULFILLED whenever the candidate hash equalled the declared one - so declaring a member as
# any 64 hex characters and then offering the same string back scored 1/1 without any bytes, any
# foton, or any producer existing. A "reproducible fact" about a thing nobody has.
# Fixed by requiring the reference to be a RECORDED FOTON OUTPUT.
#
# REFUSAL test, so it carries a benign twin: the SAME check against a member that IS a recorded
# foton output must be fulfilled. Without it, a binary that fails every check reads as PREVENTED.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/pd"; mkdir -p pd

plankton keygen k >/dev/null 2>&1
printf 'in\n' > i.txt; printf 'real bytes\n' > r.txt
plankton author --cmd make --in i.txt --out r.txt --sign k.key --add >/dev/null 2>&1
REAL=$(plankton hash r.txt)

# POSITIVE CONTROL: a member backed by a real foton output must pass.
plankton spectrum define --id ok --member m="$REAL" -o ok.json >/dev/null 2>&1
if ! plankton spectrum check ok.json --candidate m="$REAL" >/dev/null 2>&1; then
  echo "setup failed: a member that IS a recorded foton output does not check out either, so"
  echo "refusing the fabricated one proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

# The attack: a member that is 64 hex characters and nothing else.
FAKE="sha256:$(printf 'ff%.0s' {1..32})"
plankton spectrum define --id x --member m="$FAKE" -o s.json >/dev/null 2>&1
if plankton spectrum check s.json --candidate m="$FAKE" >/dev/null 2>&1; then
  echo "a fabricated member scored as fulfilled - no bytes, no foton, no producer"
  echo "VERDICT: VULNERABLE"
else
  echo "a real foton output checks out; a fabricated member does not - the check is selective"
  echo "VERDICT: PREVENTED"
fi
