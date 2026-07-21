#!/usr/bin/env bash
# needs the kton-examples checkout (for viewer/build_union.py), passed as $1.
set -e; KX="${1:-}"; [ -n "$KX" ] || { echo "VERDICT: N-A (no kton-examples)"; exit 0; }
W=$(mktemp -d); cd "$W"; export PLANKTON_DIR="$W/pd" NEKTON_DIR="$W/nd"; nekton keygen att>/dev/null 2>&1
KIRI="https://kton.dev/o/$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(open('att.pub').read().strip())).hexdigest())")"
printf '{"subject":[{"uri":"%s"}],"predicate":"https://w3id.org/security#controller","object":{"id":"did:web:fda.gov/people/senior"},"by":"CN=att","when":"2026-07-20T00:00:00Z"}' "$KIRI">b.json
nekton claim b.json att.key --add>/dev/null 2>&1
python3 "$KX/viewer/build_union.py" --out vd --keydir . --reg pd --reg nd>/dev/null 2>&1 || { echo "VERDICT: N-A"; exit 0; }
if grep -q senior vd/attested.json 2>/dev/null; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
