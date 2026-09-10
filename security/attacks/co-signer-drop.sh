#!/usr/bin/env bash
# co-signer-drop: two parties independently sign the SAME statement. A claim id covers the payload
# only, so those are one claim with two signatures - but mirroring both sources used to keep only
# the first-seen envelope, silently dropping the second signer. An attestation losing a co-signer
# on a mirror is a verification tool understating who vouched for something.
# Fixed by UNIONing the well-formed signatures of same-payload twins.
#
# Counts signatures rather than reading prose, and asserts the precondition: each source must hold
# the claim with ONE signature before the mirror, or "the mirror kept both" is vacuous.
SD="$(cd "$(dirname "$0")" && pwd)"; . "$SD/_records.sh"
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
command -v jq     >/dev/null 2>&1 || { echo "VERDICT: N-A (no jq)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }

nekton keygen a >/dev/null 2>&1; nekton keygen b >/dev/null 2>&1
printf '{"subject":[{"hash":"sha256:abababababababababababababababababababababababababababababababab"}],"predicate":"https://kton.dev/v/note","object":{"x":"1"},"by":"a","when":"2026-07-16T00:00:00Z"}' > c.json
NEKTON_DIR=rA nekton claim c.json a.key --add >/dev/null 2>&1
NEKTON_DIR=rB nekton claim c.json b.key --add >/dev/null 2>&1

# POSITIVE CONTROL: two distinct single-signature sources must exist to be merged at all.
na=$(nekton_records rA | jq -s 'map(.envelope.signatures|length)|max // 0')
nb=$(nekton_records rB | jq -s 'map(.envelope.signatures|length)|max // 0')
ka=$(nekton_records rA | jq -sr '[.[].envelope.signatures[].keyid]|unique|.[0] // ""')
kb=$(nekton_records rB | jq -sr '[.[].envelope.signatures[].keyid]|unique|.[0] // ""')
if [ "${na:-0}" != 1 ] || [ "${nb:-0}" != 1 ] || [ -z "$ka" ] || [ "$ka" = "$kb" ]; then
  echo "setup failed: expected two sources each holding the claim under a DIFFERENT single key;"
  echo "got rA=${na:-0} sig ($ka), rB=${nb:-0} sig ($kb) - nothing to lose on the mirror"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

NEKTON_DIR=m nekton mirror rA >/dev/null 2>&1; NEKTON_DIR=m nekton mirror rB >/dev/null 2>&1

# Measure the RESOLVED state, not one line of the file.
#
# A subnekton is an append-only log, so a co-signature is its own line carrying the signature it
# arrived with, and the union is the READER's job (that is what gives it a position and lets a
# cursor deliver it - AUD-04). Reading `max(signatures per line)` therefore measures the storage
# shape, not the finding: it went red the day the shape changed, exactly as this PoC's own header
# warns about the pre-#41 glob. What the finding is about is whether a co-signer can be LOST, so
# ask the two questions a consumer actually asks.
kA=$(nekton keyid a.pub 2>/dev/null | tr -d '[:space:]')
kB=$(nekton keyid b.pub 2>/dev/null | tr -d '[:space:]')
distinct=$(nekton_records m | jq -s '[.[].envelope.signatures[]?.keyid] | unique | length')
foundA=$(NEKTON_DIR=m nekton by signer "$kA" 2>/dev/null | grep -c "sha256:")
foundB=$(NEKTON_DIR=m nekton by signer "$kB" 2>/dev/null | grep -c "sha256:")

if [ -z "$kA" ] || [ -z "$kB" ] || [ "$kA" = "$kB" ]; then
  echo "setup failed: could not read two distinct signer keyids ($kA / $kB)"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
echo "distinct signers surviving the mirror: ${distinct:-0} (expected 2); \`by\` finds A=$foundA B=$foundB (expected 1 each)"
if [ "${distinct:-0}" -ge 2 ] && [ "${foundA:-0}" -ge 1 ] && [ "${foundB:-0}" -ge 1 ]; then
  echo "VERDICT: PREVENTED"
else
  echo "VERDICT: VULNERABLE"
fi
