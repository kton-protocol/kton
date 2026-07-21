#!/usr/bin/env bash
# FOCUSED TEST: author-exclusion in the two-independent-reviews branch reads
# `?fit prov:wasAttributedTo ?rauthor` from the merged default graph. If an EXTRA
# attribution edge (a plain nekton claim, signed by any key) names a decoy author,
# the SPARQL solver can pick the decoy as ?rauthor and let the REAL model author
# review its own model. Uses the SHIPPED release.rq / release.py verbatim.
set -euo pipefail
# $1 = a kton-examples checkout (for the shipped release.py/release.rq + templates/aliases), like the
# rest of the suite; $2 = attack|control.
KX="${1:?usage: fourEyes-graphpoll.sh <kton-examples-checkout> [attack|control]}"
EX="$KX/examples/12-submission"
export NEKTON_TEMPLATES="$KX/templates"
export NEKTON_ALIASES="$KX/aliases.json"
MODE="${2:-attack}"   # attack | control
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PLANKTON_DIR="$W/plankton" NEKTON_DIR="$W/nekton"; mkdir -p "$PLANKTON_DIR" "$NEKTON_DIR"
cd "$W"; mkdir -p keys files; F="files"
for k in cro-org sponsor-org analyst qc submitter; do nekton keygen "keys/$k" >/dev/null; done
keyiri(){ echo "https://kton.dev/o/$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(open('keys/$1.pub').read().strip())).hexdigest())")"; }
keyid16(){ python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(open('keys/$1.pub').read().strip())).hexdigest()[:16])"; }

# --- controller bindings: cro-org vouches analyst+qc, sponsor-org vouches submitter ---
mkctl(){ # $1=person $2=org $3=did-org
  printf '{"subject":[{"uri":"%s"}],"predicate":"https://w3id.org/security#controller","object":{"id":"did:web:%s.example/people/%s"},"by":"CN=%s","when":"2026-07-16T00:00:00Z"}' \
    "$(keyiri $1)" "$3" "$1" "$2" > "$F/$1-id.json"
  nekton claim "$F/$1-id.json" "keys/$2.key" --add >/dev/null; }
mkctl analyst   cro-org     cro
mkctl qc        cro-org     cro
mkctl submitter sponsor-org sponsor

# --- the FIT, genuinely signed by ANALYST (the real model author) ---
printf 'the model fit\n' > "$F/fit.out"
FIT=$(plankton author --cmd "Rscript fit.R" --in "$F/fit.out" --out "$F/fit.out" \
  --sign keys/analyst.key --add -o "$F/fit.dsse.json" | awk '/indexed foton/{print $3}')
echo "FIT (signed by analyst, the model author) = $FIT"

# --- reviews: qc (genuine, independent) + ANALYST reviewing its OWN fit ---
printf '%%PDF qc review\n' > "$F/qc.pdf"; printf '%%PDF analyst self review\n' > "$F/an.pdf"
nekton annotate --foton "$F/fit.dsse.json" --template gxp/review --set outcome=pass \
  --set sop=SOP-REV-002 --set report="$F/qc.pdf" --by "CN=qc" --sign keys/qc.key --add >/dev/null
nekton annotate --foton "$F/fit.dsse.json" --template gxp/review --set outcome=pass \
  --set sop=SOP-REV-002 --set report="$F/an.pdf" --by "CN=analyst" --sign keys/analyst.key --add >/dev/null
echo "reviews recorded: qc(pass) + analyst-self-review(pass)  [NO second genuine reviewer]"

if [ "$MODE" = "attack" ]; then
  # --- THE ATTACK: one false attribution edge naming the (vouched) submitter as a decoy author ---
  DECOY="urn:garbage:nobody"
  printf '{"subject":[{"hash":"%s"}],"predicate":"http://www.w3.org/ns/prov#wasAttributedTo","object":{"uri":"%s"},"by":"CN=analyst","when":"2026-07-16T00:00:00Z"}' \
    "$FIT" "$DECOY" > "$F/decoy.json"
  nekton claim "$F/decoy.json" keys/analyst.key --add >/dev/null
  echo "ATTACK: injected false edge  <fit> prov:wasAttributedTo agent:$(keyid16 submitter)  (signed by analyst)"
fi

# --- export merged graph + run the SHIPPED gate ---
plankton export --rdf --trust-keys keys > "$F/submission.ttl" 2>/dev/null
: > "$F/attestations.trig"
for f in "$NEKTON_DIR"/objects/sha256/*.json; do nekton export --nanopub --trust-keys keys "$f" >> "$F/attestations.trig" 2>/dev/null; echo >> "$F/attestations.trig"; done
HEAD="0000000000000000000000000000000000000000000000000000000000000000"
echo; echo "=== SHIPPED release.py (only two-independent-reviews matters here) ==="
python3 "$EX/release.py" "$F/submission.ttl" "$F/attestations.trig" "$EX/release.rq" \
  "$FIT" "$HEAD" "$(keyid16 cro-org)" "$(keyid16 sponsor-org)" 2>/dev/null | grep -E 'two distinct PRINCIPALS' || true
