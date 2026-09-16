#!/usr/bin/env bash
SD="$(cd "$(dirname "$0")" && pwd)"; . "$SD/_records.sh"
# fourEyes-graphpoll - can an injected ATTRIBUTION edge let a model's author review its own model?
#
# release.py decides four-eyes in the driver, not in SPARQL: it reads the fit's verified author, then
# counts reviewers who are authority-vouched, are not that author, and are a different principal. The
# attack adds one plain nekton claim - `<fit> prov:wasAttributedTo <decoy>`, signed by any key - so the
# gate can no longer tell who authored the fit, and the author's own review might stop being excluded.
#
# THIS POC PROVED NOTHING, TWICE OVER, AND IS REBUILT.
#
#   - it ended with `grep -E 'two distinct PRINCIPALS' ... || true`. release.py prints "two distinct
#     AUTHORITY-VOUCHED PRINCIPALS", so the grep never matched; `|| true` swallowed that and the script
#     exited 0 having printed nothing.
#   - it emitted NO `VERDICT:` line at all, so check.sh could not have read a result even with the grep
#     repaired - which is why it appears in neither GATED nor OPEN, and why security/self-check.sh (the
#     can-this-fail guard) never saw it either.
#   - and the scenario left ALL SEVEN conditions unticked. "four-eyes stayed unticked" was therefore
#     true with and without the attack. That is precisely the defect this suite found in envtally-CF2
#     and downgraded to INCONCLUSIVE for.
#
# So it now runs FOUR scenarios over the shipped gate and compares them. Three are controls, and they
# are what make the fourth mean anything:
#
#   honest      two genuine vouched reviewers, neither the author   -> MUST tick (the branch works)
#   selfreview  one genuine reviewer + the author reviewing itself  -> MUST NOT tick
#   attack      selfreview + the decoy attribution edge             -> MUST NOT tick (the finding)
#   honest+decoy the honest case + the decoy edge                   -> reported, not required:
#                                                                      if it un-ticks, one injected
#                                                                      claim can BLOCK a legitimate
#                                                                      release, which is a different
#                                                                      and equally real problem
set -uo pipefail
KX="${1:-}"
EX="$KX/examples/12-submission"
if [ -z "$KX" ] || [ ! -f "$EX/release.py" ] || [ ! -f "$EX/release.rq" ]; then
  echo "needs a kton-examples checkout holding examples/12-submission/release.{py,rq} (pass it as \$1)"
  echo "VERDICT: N-A (no kton-examples checkout)"; exit 0
fi
for c in plankton nekton python3; do
  command -v $c >/dev/null 2>&1 || { echo "VERDICT: N-A (no $c on PATH)"; exit 0; }
done
export NEKTON_TEMPLATES="$KX/templates" NEKTON_ALIASES="$KX/aliases.json"
ROOT="${FOUREYES_KEEP:-$(mktemp -d)}"; [ -n "${FOUREYES_KEEP:-}" ] || trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT"

# scenario <name> <second-reviewer: submitter|analyst> <decoy: yes|no>
#   prints the gate's four-eyes line, then TICKED / UNTICKED / NORUN on its own last line.
scenario() {
  local name="$1" second="$2" decoy="$3"
  local W="$ROOT/$name"; mkdir -p "$W"; ( cd "$W" || exit 1
    export PLANKTON_DIR="$W/plankton" NEKTON_DIR="$W/nekton"
    mkdir -p "$PLANKTON_DIR" "$NEKTON_DIR" keys files
    F="files"
    for k in cro-org sponsor-org analyst qc submitter; do nekton keygen "keys/$k" >/dev/null 2>&1; done
    keyiri(){ echo "https://kton.dev/o/$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(open('keys/$1.pub').read().strip())).hexdigest())")"; }
    keyid16(){ python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(open('keys/$1.pub').read().strip())).hexdigest()[:16])"; }

    mkctl(){ printf '{"subject":[{"uri":"%s"}],"predicate":"https://w3id.org/security#controller","object":{"id":"did:web:%s.example/people/%s"},"by":"CN=%s","when":"2026-07-16T00:00:00Z"}' \
        "$(keyiri $1)" "$3" "$1" "$2" > "$F/$1-id.json"
      nekton claim "$F/$1-id.json" "keys/$2.key" --add >/dev/null 2>&1; }
    mkctl analyst   cro-org     cro
    mkctl qc        cro-org     cro
    mkctl submitter sponsor-org sponsor

    printf 'the model fit\n' > "$F/fit.out"
    FIT=$(plankton author --cmd "Rscript fit.R" --in "$F/fit.out" --out "$F/fit.out" \
      --sign keys/analyst.key --add -o "$F/fit.dsse.json" 2>/dev/null | awk '/indexed foton/{print $3}')

    printf 'PDF qc review\n' > "$F/qc.pdf"; printf 'PDF second review\n' > "$F/second.pdf"
    # DISCOVER the review template; do not hard-code the companion repository's name for it. That
    # vocabulary belongs to the examples and it moves, while this PoC is about whether four-eyes can
    # be forged - a property that has nothing to do with what the template is called. A hard-coded
    # name turns a rename over there into a red gate here, and an `annotate` that silently resolves
    # nothing is how this PoC came to prove nothing at all.
    REVIEW_TPL=$(nekton templates 2>/dev/null | awk '$1 ~ /(^|\/)review$/ {print $1; exit}')
    if [ -z "$REVIEW_TPL" ]; then
      echo "no */review template in ${NEKTON_TEMPLATES:-the template dir} - cannot build the scenario"
      echo "VERDICT: INCONCLUSIVE"; exit 0
    fi
    nekton annotate --foton "$F/fit.dsse.json" --template "$REVIEW_TPL" --set outcome=pass \
      --set sop=SOP-REV-002 --set report="$F/qc.pdf" --by "CN=qc" --sign keys/qc.key --add >/dev/null 2>&1
    nekton annotate --foton "$F/fit.dsse.json" --template "$REVIEW_TPL" --set outcome=pass \
      --set sop=SOP-REV-002 --set report="$F/second.pdf" --by "CN=$second" --sign "keys/$second.key" --add >/dev/null 2>&1

    if [ "$decoy" = "yes" ]; then
      printf '{"subject":[{"hash":"%s"}],"predicate":"http://www.w3.org/ns/prov#wasAttributedTo","object":{"uri":"urn:garbage:nobody"},"by":"CN=analyst","when":"2026-07-16T00:00:00Z"}' \
        "$FIT" > "$F/decoy.json"
      nekton claim "$F/decoy.json" keys/analyst.key --add >/dev/null 2>&1
    fi

    plankton export --rdf --trust-keys keys > "$F/submission.ttl" 2>/dev/null
    : > "$F/attestations.trig"
    nekton_record_files "$NEKTON_DIR" "$F/.recs" | while IFS= read -r f; do
      nekton export --nanopub --trust-keys keys "$f" >> "$F/attestations.trig" 2>/dev/null; echo >> "$F/attestations.trig"
    done
    HEAD="0000000000000000000000000000000000000000000000000000000000000000"
    python3 "$EX/release.py" "$F/submission.ttl" "$F/attestations.trig" "$EX/release.rq" \
      "$FIT" "$HEAD" "$(keyid16 cro-org)" "$(keyid16 sponsor-org)" > verdict.txt 2>err.txt

    grep -E '^\s*\[[ x]\].*PRINCIPALS' verdict.txt | sed 's/^/    /'
    # The FOUR-EYES LINE ITSELF must be present - not merely "some checklist item".
    #
    # Testing for any item was not enough: a run that printed an earlier, unrelated condition and
    # then stopped before evaluating four-eyes fell through to UNTICKED, and UNTICKED is read below
    # as "the attack was prevented". A partial evaluation counted as a defence. Same shape as the
    # defect this script already carries a fix for, one level in: "no checklist at all" was excluded
    # and "half a checklist" was not.
    #
    # The EXIT STATUS is deliberately NOT used. release.py is a release gate: it exits 1 when the
    # release is not approved, which is the ordinary outcome of every negative scenario here. Testing
    # `rc -ne 0` turned all four into NORUN and the whole PoC INCONCLUSIVE - measured, not guessed -
    # which is the gate-refuses-the-normal-path failure rather than a stricter check. What the line's
    # presence tells us is the thing we need: that the condition was evaluated at all.
    if ! grep -qE '\[[ x]\].*PRINCIPALS' verdict.txt; then
      # Say WHY, or the next person debugging a red gate has to reproduce it to find out.
      sed 's/^/    release.py: /' err.txt | head -3
      echo "    no four-eyes line in the output - the condition was never evaluated"
      echo "NORUN"
    elif grep -q '\[x\].*PRINCIPALS' verdict.txt; then echo "TICKED"
    else echo "UNTICKED"; fi )
}

echo "=== CONTROL: two genuine vouched reviewers (qc + submitter), no decoy ==="
honest=$(scenario honest submitter no | tee /dev/stderr | tail -1)
echo
echo "=== CONTROL: one genuine reviewer + the AUTHOR reviewing its own fit ==="
selfrev=$(scenario selfreview analyst no | tee /dev/stderr | tail -1)
echo
echo "=== ATTACK: the same, plus a false <fit> prov:wasAttributedTo <decoy> edge ==="
attack=$(scenario attack analyst yes | tee /dev/stderr | tail -1)
echo
echo "=== REPORTED: the honest case, with the decoy edge injected into it ==="
poisoned=$(scenario poisoned submitter yes | tee /dev/stderr | tail -1)

echo; echo "======================================================================"
if [ "$honest" = "NORUN" ]; then
  echo "the gate produced no checklist at all - it did not run, so nothing here is evidence"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
if [ "$honest" != "TICKED" ]; then
  echo "the HONEST case (two genuine vouched reviewers, neither the author) did not tick four-eyes"
  echo "either (honest=$honest). The branch is inert in this scenario, so the attack below proves"
  echo "nothing - which is exactly what this PoC used to report as a pass."
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi
if [ "$selfrev" = "TICKED" ]; then
  echo "an author's review of its OWN fit counted toward four-eyes, with no attack needed"
  echo "VERDICT: VULNERABLE"; exit 0
fi
if [ "$attack" = "TICKED" ]; then
  echo "the injected attribution edge made the gate lose track of the author, and the author's own"
  echo "review then counted: two eyes presented as four"
  echo "VERDICT: VULNERABLE"; exit 0
fi
# A negative scenario must have EXPLICITLY come back UNTICKED. Testing only for TICKED let NORUN -
# the gate produced no checklist at all - fall through to PREVENTED below: "the attack did not tick"
# read as evidence when the attack had not run. The honest control above proves the branch CAN
# light; it says nothing about whether these two were evaluated.
for n in "self-review:$selfrev" "attack:$attack"; do
  case "${n#*:}" in
    UNTICKED) ;;
    *) echo "the ${n%%:*} scenario did not produce a checklist (${n#*:}), so its not-ticking is not a"
       echo "result. An attack that did not run cannot have been prevented."
       echo "VERDICT: INCONCLUSIVE"; exit 0 ;;
  esac
done
echo "honest=TICKED, self-review=$selfrev, attack=$attack: the branch lights for two genuine"
echo "reviewers, refuses a self-review, and the injected attribution edge does not rescue it."
if [ "$poisoned" = "UNTICKED" ]; then
  echo
  echo "NOTE, not a failure of this check: injecting the same edge into the HONEST case un-ticks it"
  echo "($poisoned). release.py fails CLOSED when the fit has more than one verified author, so any"
  echo "party able to write one claim can BLOCK a legitimate release. That is availability rather"
  echo "than forgery, and it is the correct trade for a gate - but it is a property worth knowing."
fi
echo "VERDICT: PREVENTED"
