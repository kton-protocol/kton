#!/usr/bin/env bash
# concurrency-races: two processes co-signing one record both read the stored object, both
# merge their own signature into what they read, and both write. The write is atomic
# (temp+rename, so no torn file) but the read-modify-write is not, so the second rename
# silently discards the first writer's signature.
#
# nekton serialises this with an exclusive .objects.lock; the plankton registry has no lock
# at all. This PoC races three signers on one foton id: a signs first, then b and c race.
# All three signatures must survive.
#
# Was previously a stub that printed a sentence and no VERDICT, so it could not be gated and
# the gap stayed invisible. It is executable now, and OPEN: it reports VULNERABLE until the
# plankton registry takes a lock around its union.
set -u
command -v plankton >/dev/null 2>&1 || { echo "VERDICT: N-A (no plankton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A (no temp dir)"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
printf x > f

sigs() { jq -s 'map(.envelope.signatures[]?.keyid)|unique|length' "$1"/objects/sha256/*.json 2>/dev/null || echo 0; }

# POSITIVE CONTROL. `worst` starts at the PASSING value and is only ever lowered, so a setup that
# authors nothing leaves it at 3 - and `[ "$n" -lt "$worst" ]` on an empty $n errors out rather than
# firing, which is exactly how this PoC used to report PREVENTED against a binary that did nothing.
# Prove one signature can be authored at all before racing three.
( export PLANKTON_DIR="$W/ctl"; mkdir -p "$W/ctl"
  plankton keygen a >/dev/null 2>&1
  plankton author --cmd run --in f --out f --sign a.key --add >/dev/null 2>&1 )
if [ "$(sigs "$W/ctl")" != "1" ]; then
  echo "setup failed: a single signer could not author one record, so 'no signature was lost' proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

worst=3
for round in $(seq 1 12); do
  R="$W/r$round"; mkdir -p "$R"
  ( export PLANKTON_DIR="$R"
    plankton keygen a >/dev/null 2>&1; plankton keygen b >/dev/null 2>&1; plankton keygen c >/dev/null 2>&1
    plankton author --cmd run --in f --out f --sign a.key --add >/dev/null 2>&1
    # b and c now read the same stored object and each merge only their own signature in
    plankton author --cmd run --in f --out f --sign b.key --add >/dev/null 2>&1 &
    plankton author --cmd run --in f --out f --sign c.key --add >/dev/null 2>&1 &
    wait )
  n=$(sigs "$R"); case "$n" in ''|*[!0-9]*) n=0 ;; esac
  [ "$n" -lt "$worst" ] && worst=$n
done

echo "distinct signatures surviving the race: worst of 12 rounds = $worst (expected 3)"
if [ "$worst" -ge 3 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
