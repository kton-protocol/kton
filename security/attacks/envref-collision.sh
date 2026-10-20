#!/usr/bin/env bash
# envref-collision: --env-ref pins WHICH environment ran, and it is covered for a reason - a normalizer
# or program is only trustworthy if the environment it ran in is pinned, and without the pin two
# computations in two environments collide on one action key through an environment nobody declared.
# #211 carries the pin instead when a CLASS is declared on foton/v1 (the class is then what is
# covered). That opens a path to drop the pin; it must open only for a real class.
#
# Found in review of #211 before merge: `--environment sha256:` (no hex) passed the prefix check,
# moved --env-ref out of the record, and two images collided on one record that names no class.
# FIXED: a class must be a whole content hash. This also guards the half that must not change:
# without a class, two envRefs never share an action key.
set -u
for t in plankton jq; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
printf a > in.txt; printf b > out.txt
plankton keygen k >/dev/null 2>&1
A="oci://r@sha256:$(printf 'a%.0s' $(seq 64))"; B="oci://r@sha256:$(printf 'b%.0s' $(seq 64))"
export PLANKTON_DIR="$W/reg"

# 1. No class: the pin stays covered - two envRefs, two action keys.
plankton author --statement v1 --cmd run --in in.txt --out out.txt --env-ref "$A" --sign k.key -o a.dsse >/dev/null 2>&1
plankton author --statement v1 --cmd run --in in.txt --out out.txt --env-ref "$B" --sign k.key -o b.dsse >/dev/null 2>&1
ka=$(plankton reuse a.dsse --json 2>/dev/null | jq -r .actionKey); kb=$(plankton reuse b.dsse --json 2>/dev/null | jq -r .actionKey)
case "$ka$kb" in *sha256:*sha256:*) ;; *) echo "setup failed: no action keys"; echo "VERDICT: INCONCLUSIVE"; exit 0;; esac
nocls=0; [ "$ka" = "$kb" ] && nocls=1

# 2. A class that names nothing must not open the carried path.
export PLANKTON_DIR="$W/bad"
for r in "$A" "$B"; do
  plankton author --statement v1 --cmd run --in in.txt --out out.txt --environment "sha256:" --env-ref "$r" \
    --sign k.key --add >/dev/null 2>&1
done
recs=$(plankton records --json 2>/dev/null | jq '.records | length' 2>/dev/null); recs=${recs:-0}
collided=0; [ "$recs" = 1 ] && collided=1
echo "no class, two envRefs share an action key: $nocls (want 0); malformed class, two images on one record: $collided (want 0; records: $recs)"
if [ "$nocls" = 0 ] && [ "$collided" = 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
