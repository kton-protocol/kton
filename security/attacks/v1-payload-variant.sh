#!/usr/bin/env bash
# v1-payload-variant: foton/v1 promises that the same work yields the same payload whoever records
# it, so a second producer's signature unions onto the record. Signatures only union over identical
# bytes, so that promise needs ingest to admit exactly ONE payload per v1 id. It admitted any variant
# with the same id: whitespace, key order, hex case, an extra digest or member. The first variant
# ingested then owned the record, and both honest producers were answered "already present" - their
# signatures never reached it. Two tools that serialise the same statement differently are enough.
#
# FIXED: a v1 payload must be byte-identical to the canonical statement derived from its record.
#
# The variant is signed outside plankton (openssl, Ed25519), so a positive control first proves that
# this signing path produces an envelope the registry accepts.
set -u
for t in plankton jq openssl python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
printf a > f.txt; printf b > o.txt
for k in a c tool; do plankton keygen "$k" >/dev/null 2>&1; done

# sign_raw <seed-key-file> <payload-file> <out.dsse.json>: a DSSE envelope over the given bytes.
sign_raw() {
  { printf '302e020100300506032b657004220420'; cat "$1"; } | xxd -r -p > k.der 2>/dev/null \
    || python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))' \
         <<<"302e020100300506032b657004220420$(cat "$1")" > k.der
  openssl pkey -inform DER -in k.der -out k.pem 2>/dev/null || return 1
  pt=application/vnd.in-toto+json
  { printf 'DSSEv1 %s %s %s ' "${#pt}" "$pt" "$(wc -c < "$2" | tr -d ' ')"; cat "$2"; } > pae.bin
  openssl pkeyutl -sign -inkey k.pem -rawin -in pae.bin -out sig.bin 2>/dev/null || return 1
  jq -n --arg p "$(base64 -w0 < "$2")" --arg s "$(base64 -w0 < sig.bin)" --arg pt "$pt" \
    '{payloadType:$pt, payload:$p, signatures:[{keyid:"", sig:$s}]}' > "$3"
}

plankton author --statement v1 --cmd run --in f.txt --out o.txt --sign a.key -o a.dsse >/dev/null 2>&1
jq -r .payload a.dsse | base64 -d > canon.json 2>/dev/null
[ -s canon.json ] || { echo "setup failed: no v1 record authored"; echo "VERDICT: INCONCLUSIVE"; exit 0; }

# POSITIVE CONTROL: the canonical bytes, signed this way, are admitted.
sign_raw tool.key canon.json ctl.dsse || { echo "VERDICT: N-A (openssl cannot sign Ed25519 here)"; exit 0; }
if ! PLANKTON_DIR="$W/ctl" plankton add ctl.dsse >/dev/null 2>&1; then
  echo "setup failed: a canonical payload signed outside plankton was refused, so a refusal proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

# The same statement, pretty-printed: same foton id, different bytes.
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), indent=1))' canon.json > variant.json
sign_raw tool.key variant.json variant.dsse || { echo "VERDICT: INCONCLUSIVE"; exit 0; }
export PLANKTON_DIR="$W/reg"
if plankton add variant.dsse >/dev/null 2>&1; then admitted=1; else admitted=0; fi
plankton add a.dsse >/dev/null 2>&1
plankton author --statement v1 --cmd run --in f.txt --out o.txt --sign c.key --add >/dev/null 2>&1
id=$(plankton records --json 2>/dev/null | jq -r '.records[0].fotonId')
ok=0
for k in a c; do plankton verify "$id" "$k.pub" >/dev/null 2>&1 && ok=$((ok+1)); done
echo "whitespace variant admitted: $admitted (want 0); honest producers verified on the record: $ok (want 2)"
if [ "$admitted" = 0 ] && [ "$ok" = 2 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
