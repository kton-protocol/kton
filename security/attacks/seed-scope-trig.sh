#!/usr/bin/env bash
# seed-scope-trig: a seed's scope NAME is signed record data, and `export --nanopub` wrote it
# straight into <urn:nekton:scope:...>. A name carrying `>` and a newline closed the IRI and the
# assertion graph and opened a graph of its own - e.g. a provenance graph with an attribution no
# trusted key established. Fixed by rendering the scope subject through the same escaping as every
# other record-derived IRI.
#
# Absence is what is checked, so a positive control proves the export ran first: a benign seed
# must export as exactly the four graphs of a nanopublication.
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export NEKTON_DIR="$W/nd"
nekton keygen k >/dev/null 2>&1
graphs() { grep -cE '^[^[:space:]][^{]*\{$' "$1"; }

# POSITIVE CONTROL
nekton seed lab/benign --sign k.key --when 2026-07-16T00:00:00Z -o ok.dsse >/dev/null 2>&1
nekton export --nanopub ok.dsse -o ok.trig >/dev/null 2>&1
ctl=$(graphs ok.trig 2>/dev/null)
if [ "${ctl:-0}" -ne 4 ]; then
  echo "setup failed: a benign seed did not export as 4 graphs (got ${ctl:-0}), so an absent injection proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

NAME='x> a <https://kton.dev/v/nk/Scope> .
}
<https://kton.dev/np/FORGED#provenance> {
  <https://kton.dev/np/FORGED#assertion> <http://www.w3.org/ns/prov#wasAttributedTo> <https://kton.dev/agent/c0ffee> .
}
sub:assertion {
  <urn:nekton:scope:y'
# Refusing the name at authoring would also be a fix: then there is nothing to export.
if ! nekton seed "$NAME" --sign k.key --when 2026-07-16T00:00:00Z -o bad.dsse >/dev/null 2>&1; then
  echo "the hostile scope name was refused at authoring"; echo "VERDICT: PREVENTED"; exit 0
fi
nekton export --nanopub bad.dsse -o bad.trig >/dev/null 2>&1
g=$(graphs bad.trig 2>/dev/null); f=$(grep -cE '^[[:space:]]*<https://kton\.dev/np/FORGED' bad.trig 2>/dev/null)
echo "benign control: $ctl graphs; hostile seed: ${g:-0} graphs (expected 4), forged graph lines: ${f:-0} (expected 0)"
if [ "${g:-0}" -eq 4 ] && [ "${f:-0}" -eq 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
