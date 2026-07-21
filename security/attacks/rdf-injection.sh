#!/usr/bin/env bash
set -e; W=$(mktemp -d); cd "$W"; export NEKTON_DIR="$W/nd"; nekton keygen k>/dev/null 2>&1
H="sha256:$(printf 'ab%.0s' {1..32})"
printf '{"subject":[{"hash":"%s"}],"predicate":"pav:reviewedBy","object":{"status":"x://a> ; <http://www.w3.org/ns/prov#wasAttributedTo> <https://kton.dev/agent/CEO-BOARD"},"by":"CN=low","when":"2026-07-16T00:00:00Z"}' "$H">c.json
nekton claim c.json k.key c.dsse --add>/dev/null 2>&1
if nekton export --nanopub c.dsse 2>/dev/null | grep -qE 'wasAttributedTo> <https://kton.dev/agent/CEO-BOARD>'; then echo "VERDICT: VULNERABLE"; else echo "VERDICT: PREVENTED"; fi
