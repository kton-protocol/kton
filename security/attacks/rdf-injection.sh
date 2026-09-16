#!/usr/bin/env bash
# rdf-injection: a claim's object values end up inside an N-Triples nanopublication. A value
# containing `> ; <...>` used to CLOSE the IRI and open a new triple, letting a low-privilege claim
# publish `prov:wasAttributedTo <https://kton.dev/agent/CEO-BOARD>` as if the board had said it.
# Fixed by escaping/refusing values that cannot be serialised as a single term.
#
# Like export-attribution, this greps for a string that must be ABSENT, so an export producing
# NOTHING used to read as PREVENTED. It now proves the export ran and emitted this claim first.
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
export NEKTON_DIR="$W/nd"
nekton keygen k >/dev/null 2>&1
H="sha256:$(printf 'ab%.0s' {1..32})"

# POSITIVE CONTROL: a BENIGN claim of the same shape must export as a nanopublication. If that does
# not work, "the hostile value did not appear" says nothing about escaping.
printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/reviewed","object":{"status":"ok"},"by":"CN=low","when":"2026-07-16T00:00:00Z"}' "$H" > ok.json
nekton claim ok.json k.key ok.dsse --add >/dev/null 2>&1
ctl=$(nekton export --nanopub ok.dsse 2>/dev/null | grep -c .)
if [ "${ctl:-0}" -lt 1 ]; then
  echo "setup failed: a benign claim produced no nanopublication, so an absent injection proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

printf '{"subject":[{"hash":"%s"}],"predicate":"pav:reviewedBy","object":{"status":"x://a> ; <http://www.w3.org/ns/prov#wasAttributedTo> <https://kton.dev/agent/CEO-BOARD"},"by":"CN=low","when":"2026-07-16T00:00:00Z"}' "$H" > c.json
# The claim may legitimately be REFUSED at authoring - that is also a fix, and then there is no
# nanopublication to inspect and nothing was injected.
nekton claim c.json k.key c.dsse --add >/dev/null 2>&1
n=$(nekton export --nanopub c.dsse 2>/dev/null | grep -cE 'wasAttributedTo> <https://kton.dev/agent/CEO-BOARD>')
echo "benign control emitted $ctl triples; injected wasAttributedTo triples: ${n:-0} (expected 0)"
if [ "${n:-0}" -eq 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
