#!/usr/bin/env bash
# nekton-vote (hardened) - bash EXECUTOR for the vote, ZERO Python.
#
# Dependencies: bash, sha256sum, base64, openssl, and jq (jq used ONLY to parse signed claim
# payloads). Everything else - hashing, deterministic emission, DSSE Ed25519 signing AND
# VERIFICATION - is coreutils + openssl. No Python.
#
# Boundary unchanged: nekton records claims; THIS tool runs the count; output is a plankton
# foton Statement that `plankton record` ingests.
#
# SECURITY (round-2 C1): a ballot is COUNTED by its VERIFIED signing keyid, never the self-declared
# `by` label. --keys is the directory of the eligible voters' Ed25519 PEM public keys; the roster's
# voter ids ARE keyids. Each ballot's DSSE signature is verified with openssl against the eligible
# pubkeys and counted under the VERIFYING keyid; a ballot that verifies against no eligible key
# (forged, ineligible, or unsigned) is dropped. `by` is display-only and never confers a vote.
# (Sibling of the canonical `nekton-vote` fix; the .jq build verifies inline with openssl, no Python.)
#
# Determinism: input files hashed as RAW bytes (plankton spec §1); result.json & the foton
# Statement emitted in a FIXED byte layout (sorted voters/choices/inputs); DSSE signs the
# literal statement bytes. Re-run -> identical bytes -> identical hash. No wall-clock, no random.
set -euo pipefail

MOTION= ROSTER= BALLOTS= METHOD="liquid-democracy@0.1" KEY= OUT="result.json" KEYS=
while [[ $# -gt 0 ]]; do case "$1" in
  --motion) MOTION="$2"; shift 2;; --roster) ROSTER="$2"; shift 2;;
  --ballots) BALLOTS="$2"; shift 2;; --method) METHOD="$2"; shift 2;;
  --keys) KEYS="$2"; shift 2;;
  --sign) KEY="$2"; shift 2;; -o) OUT="$2"; shift 2;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; done
: "${MOTION:?--motion}" "${ROSTER:?--roster}" "${BALLOTS:?--ballots}" "${KEY:?--sign}" \
  "${KEYS:?--keys DIR of the eligible voters .pub keys is required to verify ballots}"

filehash() { printf 'sha256:%s' "$(sha256sum "$1" | cut -d' ' -f1)"; }

# ---- read motion + roster via jq (small, fixed reads) ------------------------------------
TOPIC="$(jq -r '.topic' "$MOTION")"
MOTION_ID="$(jq -r '.id' "$MOTION")"
mapfile -t CHOICES < <(jq -r '.choices[]' "$MOTION" | sort)
declare -A WEIGHT
while IFS=$'\t' read -r vid w; do WEIGHT["$vid"]="$w"; done < <(jq -r '.voters[] | [.id,.weight] | @tsv' "$ROSTER")

# ---- the ONE jq use that matters: extract fields from a signed claim payload -------------
extract() { # $1 claim dsse file -> declared<TAB>kind<TAB>subject<TAB>object<TAB>context<TAB>when
  jq -r '.payload' "$1" | base64 -d | jq -r '
    [ .predicate.by,
      (.predicate.predicate.uri | split("/") | last),
      (.subject[0].uri // ("sha256:" + .subject[0].digest.sha256)),
      (.predicate.object.uri // .predicate.object.choice // ""),
      (.predicate.context.uri // ""),
      .predicate.when ] | @tsv'
}

# ---- keyid of a PEM public key: sha256(raw 32-byte Ed25519 pubkey), first 16 hex ---------
# SAME derivation the signing path below uses (openssl pkey -pubout DER | tail -c 32 = the raw key),
# so a voter's roster id (a keyid) matches the key that will verify their ballot.
keyid_of_pub() { openssl pkey -pubin -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-16; }

# ---- verify a ballot's DSSE Ed25519 signature against one pubkey (openssl, no Python) -----
# Reconstructs the DSSE PAE exactly as the signer built it (DSSEv1 <tlen> <ptype> <plen> <payload>)
# and one-shot-verifies with openssl -rawin. Exit 0 iff the signature is valid for this key.
verify_ballot() { # $1 ballot dsse file, $2 pubkey PEM
  local f="$1" pub="$2" pt pl sig tmp sigf rc
  pt="$(jq -r '.payloadType' "$f")"
  pl="$(jq -r '.payload' "$f" | base64 -d)"          # raw payload bytes (the literal statement)
  tmp="$(mktemp)"; sigf="$(mktemp)"
  { printf 'DSSEv1 %s %s %s ' "${#pt}" "$pt" "$(printf '%s' "$pl" | wc -c)"; printf '%s' "$pl"; } > "$tmp"
  jq -r '.signatures[0].sig' "$f" | base64 -d > "$sigf"
  openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$tmp" -sigfile "$sigf" >/dev/null 2>&1; rc=$?
  rm -f "$tmp" "$sigf"; return $rc
}

# ---- map each eligible voter's keyid -> its public key file (roster is keyed BY keyid) ----
declare -A PUBFILE
for pf in "$KEYS"/*.pub; do
  [[ -e "$pf" ]] || continue
  kid="$(keyid_of_pub "$pf")"; [[ -n "$kid" ]] && PUBFILE["$kid"]="$pf"
done

# ---- read the sealed ballot box: one SIGNATURE-VERIFIED claim -> one counted vote --------
declare -A VOTE VOTE_KEY DELEG DELEG_KEY
declare -a INPUT_LINES                       # "name<TAB>sha256:hex"
for f in "$BALLOTS"/*.json; do
  h="$(filehash "$f")"; INPUT_LINES+=("ballots/$(basename "$f")"$'\t'"$h")
  IFS=$'\t' read -r declared kind subject object context when < <(extract "$f")
  # SECURITY (round-2 C1): identity is the VERIFIED signing keyid, never the self-declared `by`. Find
  # the eligible voter whose PUBLIC KEY actually verifies this ballot's DSSE signature; drop any ballot
  # that verifies against no eligible key (forged / ineligible / unsigned). `declared` is diagnostics only.
  signer=""
  for kid in "${!WEIGHT[@]}"; do
    [[ -n "${PUBFILE[$kid]:-}" ]] || continue
    if verify_ballot "$f" "${PUBFILE[$kid]}"; then signer="$kid"; break; fi
  done
  [[ -n "$signer" ]] || continue
  key="${when}|${h}"
  if [[ "$kind" == "vote" && "$subject" == "$MOTION_ID" ]]; then
    if [[ -z "${VOTE_KEY[$signer]:-}" || "$key" > "${VOTE_KEY[$signer]}" ]]; then
      VOTE["$signer"]="$object"; VOTE_KEY["$signer"]="$key"; fi
  elif [[ "$kind" == "delegate" && "$context" == "$TOPIC" ]]; then
    if [[ -z "${DELEG_KEY[$signer]:-}" || "$key" > "${DELEG_KEY[$signer]}" ]]; then
      DELEG["$signer"]="$object"; DELEG_KEY["$signer"]="$key"; fi
  fi
done

# ---- deterministic resolution -----------------------------------------------------------
resolve() { local v="$1"; shift; local seen=" $* "
  if [[ -n "${VOTE[$v]:-}" ]]; then echo "${VOTE[$v]}|direct"; return; fi
  if [[ -n "${DELEG[$v]:-}" ]]; then local t="${DELEG[$v]}"
    if [[ "$seen" == *" $t "* || -z "${WEIGHT[$t]:-}" ]]; then echo "ABSTAIN|cycle-or-dangling"; return; fi
    resolve "$t" $* "$v"; return; fi
  echo "ABSTAIN|no-vote"; }

declare -A TALLY; for c in "${CHOICES[@]}"; do TALLY["$c"]=0; done
mapfile -t VOTERS < <(printf '%s\n' "${!WEIGHT[@]}" | sort)
declare -a ABSTAIN; TURNOUT=0; declare -A RESV RESC
for v in "${VOTERS[@]}"; do
  r="$(resolve "$v" "$v")"; choice="${r%%|*}"; via="${r##*|}"
  if [[ "$choice" == "ABSTAIN" ]]; then ABSTAIN+=("$v"); RESC["$v"]="null"; RESV["$v"]="$via"
  else TALLY["$choice"]=$(( TALLY["$choice"] + WEIGHT["$v"] )); TURNOUT=$(( TURNOUT + WEIGHT["$v"] ))
       RESC["$v"]="\"$choice\""; RESV["$v"]="$via"; fi
done

WINNER=null; best=-1; tie=0
for c in "${CHOICES[@]}"; do t=${TALLY[$c]}
  if (( t > best )); then best=$t; WINNER="\"$c\""; tie=0
  elif (( t == best )); then tie=1; fi; done
(( TURNOUT > 0 )) || WINNER=null; (( tie == 1 )) && WINNER=null

# ---- emit result.json in a FIXED deterministic layout (hashed as raw bytes) --------------
ROSTER_H="$(filehash "$ROSTER")"; MOTION_H="$(filehash "$MOTION")"
{
  printf '{\n'
  printf '  "abstentions": ['
  first=1; for v in $(printf '%s\n' "${ABSTAIN[@]:-}" | { grep -v '^$' || true; } | sort); do
    [[ $first == 1 ]] && first=0 || printf ', '; printf '"%s"' "$v"; done; printf '],\n'
  printf '  "input_set": {\n    "ballots": ['
  first=1; for h in $(printf '%s\n' "${INPUT_LINES[@]}" | cut -f2 | sort); do
    [[ $first == 1 ]] && first=0 || printf ', '; printf '"%s"' "$h"; done
  printf '],\n    "motion": "%s",\n    "roster": "%s"\n  },\n' "$MOTION_H" "$ROSTER_H"
  printf '  "method": "%s",\n  "motion": "%s",\n' "$METHOD" "$MOTION_ID"
  printf '  "resolution": {\n'
  first=1; for v in "${VOTERS[@]}"; do
    [[ $first == 1 ]] && first=0 || printf ',\n'
    printf '    "%s": {"choice": %s, "via": "%s"}' "$v" "${RESC[$v]}" "${RESV[$v]}"; done
  printf '\n  },\n  "tally": {'
  first=1; for c in "${CHOICES[@]}"; do
    [[ $first == 1 ]] && first=0 || printf ', '; printf '"%s": %s' "$c" "${TALLY[$c]}"; done
  printf '},\n  "turnout": %s,\n  "winner": %s\n}\n' "$TURNOUT" "$WINNER"
} > "$OUT"
RESULT_H="$(filehash "$OUT")"

# ---- build protocol descriptor (fixed bytes) + ref --------------------------------------
DESC='{"method":{"id":"'"${METHOD%@*}"'","version":"'"${METHOD#*@}"'","rules":{"cycle_without_direct_vote":"abstain","delegation_scoped_to_topic":true,"direct_vote_overrides_delegation":true,"multiple_votes":"latest-when-then-greatest-hash","voter_order":"sorted-by-id"}},"env":{"tool":"nekton-vote","version":"0.1"},"outputs_capture":["result.json"]}'
PROTO_REF="sha256:$(printf '%s' "$DESC" | sha256sum | cut -d' ' -f1)"

# ---- build foton Statement (fixed bytes; inputs sorted by hash) -------------------------
INPUTS_JSON=""; first=1
all_inputs="$(printf 'roster.json\t%s\nmotion.json\t%s\n' "$ROSTER_H" "$MOTION_H"; printf '%s\n' "${INPUT_LINES[@]}")"
while IFS=$'\t' read -r name h; do
  [[ -z "$name" ]] && continue
  [[ $first == 1 ]] && first=0 || INPUTS_JSON+=","
  INPUTS_JSON+='{"name":"'"$name"'","digest":{"sha256":"'"${h#sha256:}"'"}}'
done < <(printf '%s\n' "$all_inputs" | sort -t$'\t' -k2)
STMT='{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"result.json","digest":{"sha256":"'"${RESULT_H#sha256:}"'"}}],"predicateType":"https://kton.dev/foton/v0","predicate":{"inputs":['"$INPUTS_JSON"'],"protocol":{"kind":"tally","ref":"'"$PROTO_REF"'","descriptor":'"$DESC"'}}}'
printf '%s' "$STMT" > tally.foton.statement.json

# ---- DSSE sign the literal statement bytes (openssl) ------------------------------------
PTYPE='application/vnd.in-toto+json'
KEYID="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-16)"
PB64="$(printf '%s' "$STMT" | base64 -w0)"; PLEN=$(printf '%s' "$STMT" | wc -c); TLEN=${#PTYPE}
TMP="$(mktemp)"; { printf 'DSSEv1 %s %s %s ' "$TLEN" "$PTYPE" "$PLEN"; printf '%s' "$STMT"; } > "$TMP"
SIG="$(openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$TMP" 2>/dev/null | base64 -w0)"; rm -f "$TMP"
printf '{"payloadType":"%s","payload":"%s","signatures":[{"keyid":"%s","sig":"%s"}]}\n' \
  "$PTYPE" "$PB64" "$KEYID" "$SIG" > tally.foton.dsse.json

echo "nekton-vote: topic        $TOPIC"
echo "nekton-vote: ballot box   ${#INPUT_LINES[@]} claims (sealed, raw-byte hashed)"
printf 'nekton-vote: tally        '; for c in "${CHOICES[@]}"; do printf '%s=%s ' "$c" "${TALLY[$c]}"; done; echo
echo "nekton-vote: winner       $WINNER   abstain=${ABSTAIN[*]:-none}"
echo "nekton-vote: result.json  $RESULT_H"
echo "nekton-vote: protocol.ref $PROTO_REF"
echo "nekton-vote: signed foton tally.foton.dsse.json (kind=tally, keyid $KEYID)"
echo "             -> plankton record --foton tally.foton.dsse.json"
