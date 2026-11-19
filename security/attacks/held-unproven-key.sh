#!/usr/bin/env bash
# held-unproven-key: Position.Held (#260) lets a consumer that follows a store by Records(since) notice
# that records were removed from outside (a checkout or merge). As first proposed it XORed sha256 over
# keys read from disk unverified - a line's claimId field, an object file's name. A line that is not a
# record counted although Records never delivers it, and because XOR is linear, a removal could be
# cancelled by appending claimId-only lines chosen by Gaussian elimination: Held unchanged, a record gone.
#
# FIXED (#261 review H1): a key counts only where the content proves it (the line's payload hashes to
# its claimId) and the line carries at least one signature (#270, Add's own minimum). Held detects LOSS,
# not a forger - the doc says so; this gate holds that claim: a claimId-only line does not count, and a
# removal hidden behind claimId-only lines, or behind unsigned lines with a hash-valid payload, changes Held.
set -u
for t in nekton python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
nekton keygen a >/dev/null 2>&1
for i in 1 2 3; do
  printf '{"subject":[{"uri":"urn:x:%s"}],"predicate":"https://kton.dev/v/x","by":"a","when":"2026-11-19T10:00:0%sZ"}' $i $i > s.json
  nekton claim s.json a.key --add --registry A >/dev/null 2>&1
done
held() { NEKTON_DIR=A nekton position --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("held",""))' 2>/dev/null; }
F=$(python3 -c 'import glob,os,sys;fs=glob.glob("A/objects/**/*.nekton.jsonl",recursive=True);print(max(fs,key=lambda f:sum(1 for _ in open(f))) if fs else "")')
h0=$(held)
[ -n "$h0" ] && [ -n "$F" ] || { echo "setup failed: no held digest or no store file"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
n=$(grep -c . "$F"); [ "$n" -ge 2 ] || { echo "setup failed: want two records in one file, have $n"; echo "VERDICT: INCONCLUSIVE"; exit 0; }

# 1. a claimId-only line (not a record) must not change Held
cp "$F" keep
python3 -c 'import json,os;print(json.dumps({"claimId":"sha256:"+os.urandom(32).hex()}))' >> "$F"
h1=$(held); cp keep "$F"
# 2./3. remove one record and append lines whose keys XOR to its key - claimId-only lines (2), and
#        lines whose payload hashes to their claimId but carry NO signature (3, #270): Held must change
cp keep "$F"
forge() {  # <file> <mode: bare|unsigned>
python3 - "$1" "$2" <<'PY'
import base64, hashlib, json, os, sys
path, mode = sys.argv[1], sys.argv[2]
lines = [l for l in open(path).read().splitlines() if l.strip()]
H = lambda s: int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")
target = H(json.loads(lines[-1])["claimId"])
pays = [os.urandom(24) for _ in range(320)]
cands = ["sha256:" + (hashlib.sha256(p).hexdigest() if mode == "unsigned" else os.urandom(32).hex()) for p in pays]
basis = {}
for i, c in enumerate(cands):
    v, s = H(c), {i}
    while v:
        p = v.bit_length() - 1
        if p not in basis:
            basis[p] = (v, s); break
        v ^= basis[p][0]; s ^= basis[p][1]
v, s = target, set()
while v:
    p = v.bit_length() - 1
    v ^= basis[p][0]; s ^= basis[p][1]
def line(i):
    if mode == "bare":
        return json.dumps({"claimId": cands[i]})
    return json.dumps({"claimId": cands[i], "envelope": {"payloadType": "application/vnd.in-toto+json",
                       "payload": base64.b64encode(pays[i]).decode(), "signatures": []}})
open(path, "w").write("\n".join(lines[:-1] + [line(i) for i in sorted(s)]) + "\n")
PY
}
forge "$F" bare; h2=$(held); cp keep "$F"
forge "$F" unsigned; h3=$(held)
counted=0; [ "$h1" != "$h0" ] && counted=1
hidden=0; [ "$h2" = "$h0" ] && hidden=1
hidden_unsigned=0; [ "$h3" = "$h0" ] && hidden_unsigned=1
echo "a claimId-only line changed held: $counted (want 0); a removal hidden behind claimId-only lines: $hidden (want 0); behind unsigned hash-valid lines: $hidden_unsigned (want 0)"
if [ "$counted" = 0 ] && [ "$hidden" = 0 ] && [ "$hidden_unsigned" = 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
