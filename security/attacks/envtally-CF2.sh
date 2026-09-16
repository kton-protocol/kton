#!/usr/bin/env bash
SD="$(cd "$(dirname "$0")" && pwd)"; . "$SD/_records.sh"
# envtally-CF2 - does the release gate's "env-qualified" condition read the CITED fulfilment, or only
# the numbers the claim reports about itself?
#
# CLAIM UNDER TEST (README + 10-tool-spectrum): backing a qualifies-as with a re-derivable
# spectrum-check foton means the gate requires a real fulfilment, "not a bare 3/3 assertion".
#
# release.rq's env-qualified branch requires the qualification to cite a fulfilment foton that
# CONSUMED the env-spectrum (`?chk prov:used ?env`) and then FILTERs on the claim's own tally
# (`?nful = ?ntot`). A spectrum check that FAILED still consumed the spectrum, so it carries the same
# prov:used edge - and the tally the filter reads is written by whoever authored the qualification.
#
# So this runs TWO scenarios over the same shipped gate and compares:
#
#   control  candidate matches all three members; the foton records 3/3; the claim says 3/3
#            -> env-qualified MUST light, or the branch is inert and nothing below means anything
#   attack   candidate matches two of three; the foton records 2/3; the claim still SAYS 3/3
#            -> if env-qualified lights, the gate never read the fulfilment it demanded
#
# Reuses the SHIPPED release.rq and release.py verbatim.
set -uo pipefail
# release.py and release.rq are SHIPPED BY kton-examples, in examples/12-submission - not next to
# this script. EXDIR pointed at the attacks directory, so the python3 call below could never find
# them: the PoC ran to the end and printed a verdict over a release gate that was never invoked.
# check.sh passes a kton-examples checkout as $1; without one this cannot run at all, and says so.
KX="${1:-}"
EXDIR="$KX/examples/12-submission"
if [ -z "$KX" ] || [ ! -f "$EXDIR/release.py" ] || [ ! -f "$EXDIR/release.rq" ]; then
  echo "needs a kton-examples checkout holding examples/12-submission/release.{py,rq} (pass it as \$1)"
  echo "VERDICT: N-A (no kton-examples checkout)"; exit 0
fi
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
command -v nekton   >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
command -v python3  >/dev/null 2>&1 || { echo "VERDICT: N-A (no python3)"; exit 0; }
# ENVTALLY_KEEP=<dir> keeps both scenarios' graphs for inspection; otherwise they are temporary.
W="${ENVTALLY_KEEP:-$(mktemp -d)}"; [ -n "${ENVTALLY_KEEP:-}" ] || trap 'rm -rf "$W"' EXIT; mkdir -p "$W"

# scenario <name> <covariate-candidate-content> <claimed-nful> <claimed-ntot>
#   builds a whole submission graph and runs the shipped gate over it.
#   Prints the gate's checklist indented, and echoes TICKED / UNTICKED / NORUN on the last line.
scenario() {
  local name="$1" covariate="$2" nful="$3" ntot="$4"
  local d="$W/$name"; mkdir -p "$d"; ( cd "$d" || exit 1
    export PLANKTON_DIR="$d/plankton" NEKTON_DIR="$d/nekton"
    mkdir -p "$PLANKTON_DIR" "$NEKTON_DIR"
    plankton keygen author >/dev/null 2>&1; nekton keygen qc >/dev/null 2>&1

    # Each reference must be a RECORDED FOTON OUTPUT: since the spectrum-existence fix, a member that
    # is merely 64 hex characters scores 0/3 - no bytes, no foton, no producer. Authoring them is what
    # makes the honest control honest.
    printf 'seed\n' > seed.in
    for m in onecomp twocomp covariate; do
      printf 'ref-%s-correct\n' "$m" > "ref-$m.out"
      plankton author --cmd "make $m" --in seed.in --out "ref-$m.out" --sign author.key --add >/dev/null 2>&1
    done
    HA=$(plankton hash ref-onecomp.out); HB=$(plankton hash ref-twocomp.out); HC=$(plankton hash ref-covariate.out)
    plankton spectrum define --id exploit-suite --of "the tool under test" \
      --member "test-onecomp=$HA" --member "test-twocomp=$HB" --member "test-covariate=$HC" \
      -o spectrum.json >/dev/null 2>&1
    ENV=$(plankton hash spectrum.json)

    cp ref-onecomp.out cand-onecomp.out
    cp ref-twocomp.out cand-twocomp.out
    printf '%s\n' "$covariate" > cand-covariate.out
    CA=$(plankton hash cand-onecomp.out); CB=$(plankton hash cand-twocomp.out); CC=$(plankton hash cand-covariate.out)

    # The fulfilment foton records whatever the check actually found - 3/3 or 2/3.
    plankton spectrum check spectrum.json \
      --candidate "test-onecomp=$CA" --candidate "test-twocomp=$CB" --candidate "test-covariate=$CC" \
      > fulfilment.txt 2>&1 || true
    CHECK=$(plankton author --cmd "plankton spectrum check exploit-suite" \
      --in spectrum.json --in cand-onecomp.out --in cand-twocomp.out --in cand-covariate.out \
      --out fulfilment.txt --sign author.key --add 2>/dev/null | awk '/indexed foton/{print $3}')

    printf 'the model fit\n' > fit.out
    FIT=$(plankton author --cmd "Rscript fit.R" --in fit.out --out fit.out --environment "$ENV" \
      --sign author.key --add -o fit.dsse.json 2>/dev/null | awk '/indexed foton/{print $3}')
    printf 'oci://example/env:1.0@sha256:%064d\n' 0 > image.txt
    OCI=$(plankton hash image.txt)

    # The qualification reports its OWN tally - the numbers release.rq's FILTER reads.
    printf '{"subject":[{"hash":"%s","uri":"oci://example/env:1.0"}],"predicate":"https://kton.dev/v/qualifies-as","object":{"id":"https://kton.dev/o/%s","fulfilment":"https://kton.dev/o/%s","membersFulfilled":"%s","membersTotal":"%s"},"why":"image fulfils exploit-suite (%s/%s)","by":"CN=qc","when":"2026-07-16T00:00:00Z"}' \
      "$OCI" "${ENV#sha256:}" "${CHECK#sha256:}" "$nful" "$ntot" "$nful" "$ntot" > qual.json
    nekton claim qual.json qc.key --add >/dev/null 2>&1

    plankton export --rdf > submission.ttl 2>/dev/null
    : > attestations.trig
    nekton_record_files "$NEKTON_DIR" .recs | while IFS= read -r f; do
      nekton export --nanopub "$f" >> attestations.trig 2>/dev/null; echo >> attestations.trig
    done

    HEAD="sha256:$(printf 0 | plankton hash /dev/stdin 2>/dev/null | sed 's/sha256://' || echo 0)"
    # release.py's contract is `ttl trig query FIT_HASH HEAD_HASH [trusted keyids...]`. This call used
    # to pass fit.dsse.json as a fourth argument, so fit_hash was the FILENAME and head_hash was the
    # foton id: the gate was bound to a submission that does not exist and could not light a single
    # condition, whatever the graph said. Together with the wrong EXDIR, that is why this PoC never
    # ran its own scenario.
    python3 "$EXDIR/release.py" submission.ttl attestations.trig "$EXDIR/release.rq" \
      "$FIT" "$HEAD" > verdict.txt 2>release.err

    echo "  fit=${FIT:0:20}…  fulfilment=${CHECK:0:20}…  env=${ENV:0:20}…"
    echo "  recorded by the fulfilment foton: $(grep -oE '[0-9]+/[0-9]+ member\(s\) fulfilled' fulfilment.txt | head -1)"
    echo "  asserted by the qualifies-as:     $nful/$ntot"
    grep -E '^\s*\[[ x]\].*environment is qualified' verdict.txt | sed 's/^/    /'
    if ! grep -qE '\[[ x]\]' verdict.txt; then echo "NORUN"
    elif grep -q '\[x\].*environment is qualified' verdict.txt; then echo "TICKED"
    else echo "UNTICKED"; fi )
}

echo "=== CONTROL: an honest 3/3 - the candidate matches every member ==="
control=$(scenario control 'ref-covariate-correct' 3 3 | tee /dev/stderr | tail -1)
echo
echo "=== ATTACK: the foton records 2/3, the qualification asserts 3/3 ==="
attack=$(scenario attack 'cand-covariate-WRONG' 3 3 | tee /dev/stderr | tail -1)

echo; echo "======================================================================"
if [ "$control" = "NORUN" ] || [ "$attack" = "NORUN" ]; then
  echo "the gate produced no checklist (control=$control attack=$attack) - it did not run, so nothing"
  echo "here is evidence"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
if [ "$control" != "TICKED" ]; then
  # Without this, "the attack did not light it" would be indistinguishable from "this branch never
  # lights at all", which is what the earlier version of this PoC actually reported.
  echo "the HONEST 3/3 did not light env-qualified either (control=$control), so the branch is inert"
  echo "in this scenario and the attack below proves nothing about the tally check"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
if [ "$attack" = "TICKED" ]; then
  echo "env-qualified lights for a qualification that ASSERTS 3/3 while the fulfilment foton it cites"
  echo "records 2/3. The FILTER(?nful = ?ntot) in release.rq compares the claim's own numbers, which"
  echo "the author of the claim writes; it never reads the verdict of the foton it demanded. release.rq"
  echo "says so itself: \"A forged N==M is caught by the regulator's own spectrum re-run, Act 8a\" -"
  echo "so the guarantee lives OUTSIDE this gate, and a reader of the gate alone would not know."
  echo "VERDICT: VULNERABLE"
else
  echo "env-qualified lights on an honest 3/3 and not on a forged one: the gate reads the cited"
  echo "fulfilment, not just the claim's self-report."
  echo "VERDICT: PREVENTED"
fi
