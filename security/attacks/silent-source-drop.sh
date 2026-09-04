#!/usr/bin/env bash
# silent-source-drop: a query over several --source registries used to skip an unreadable one and
# answer from the rest, exit 0. An incomplete answer that looks complete is the worst outcome for a
# verification tool: "no producer" then means "none, as far as the sources I could open".
# Fixed by failing loudly when a named source cannot be read.
#
# REFUSAL test, so it carries a benign twin: the SAME query over only the good source must succeed.
# Otherwise a binary that cannot answer anything reads as "correctly refused".
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export PLANKTON_DIR="$W/S"; mkdir -p S

plankton keygen k >/dev/null 2>&1
printf 'in\n' > f; printf 'out\n' > o
plankton author --cmd c --in f --out o --sign k.key --add >/dev/null 2>&1
H=$(plankton hash f)

if ! plankton uses --source S "$H" >/dev/null 2>&1; then
  echo "setup failed: the query fails over the GOOD source alone, so refusing it with a missing"
  echo "source added proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

if plankton uses --source S --source "/tmp/NOPE-$$" "$H" >/dev/null 2>&1; then
  echo "answered over a source it could not open, exit 0 - an incomplete answer presented as complete"
  echo "VERDICT: VULNERABLE"
else
  echo "good source alone answers; adding an unreadable source fails loudly - the check is selective"
  echo "VERDICT: PREVENTED"
fi
