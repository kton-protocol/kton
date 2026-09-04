#!/usr/bin/env bash
# read-path-ungated: the READ path applied none of the gates `Add` enforces. A record that ingest
# refuses was fully indexed if it arrived by any other route - and both kernels document git merge as
# a supported federation transport, which bypasses Add entirely. So every ingest-gate finding in this
# report was re-openable through a path the design endorses.
#
# Two shapes, one per kernel:
#   nekton  - the exact record `when-unvalidated` (GATED, PREVENTED) proves is rejected, appended to
#             a store file by hand: indexed and printed as an ordinary claim. That PoC only ever
#             exercised the CLI ingest path.
#   plankton - an UNSIGNED record (SPEC §8 admits only signed ones): indexed, served by `records`.
#
# FIXED #91: index/apply run the same gates, skipping and naming what they refuse. Skipped rather
# than fatal, because one planted file must not disable reads over every good record
# (corrupt-poisons-read); `--strict` is the loud form for callers who need it.
set -u
for b in nekton plankton python3; do command -v $b >/dev/null 2>&1 || { echo "VERDICT: N-A (no $b)"; exit 0; }; done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }

export NEKTON_DIR="$W/n" PLANKTON_DIR="$W/p"
nekton keygen k >/dev/null 2>&1
plankton keygen pk >/dev/null 2>&1
H="sha256:$(printf x | sha256sum | cut -d' ' -f1)"
printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"x":"1"},"by":"a","when":"2026-07-16T00:00:00Z"}' "$H" > ok.json
nekton claim ok.json k.key --add >/dev/null 2>&1
printf a > f.txt
plankton author --cmd run --in f.txt --out f.txt --sign pk.key --add >/dev/null 2>&1

# nekton: hand-append the record Add rejects for a non-RFC3339 `when`
python3 - "$(printf x | sha256sum | cut -d' ' -f1)" <<'PY'
import json, base64, hashlib, sys, glob
st = {"_type":"https://in-toto.io/Statement/v1","predicateType":"https://kton.dev/claim/v0",
      "subject":[{"digest":{"sha256":sys.argv[1]}}],
      "predicate":{"by":"a","object":{"x":"1"},
                   "predicate":{"uri":"https://kton.dev/v/note"},"when":"whenever-you-like"}}
pl = json.dumps(st, separators=(',',':'), sort_keys=True).encode()
env = {"payloadType":"application/vnd.in-toto+json","payload":base64.b64encode(pl).decode(),
       "signatures":[{"keyid":"0"*16,"sig":base64.b64encode(b"\0"*64).decode()}]}
f = glob.glob("n/objects/*.jsonl")[0]
open(f,"a").write(json.dumps({"claimId":"sha256:"+hashlib.sha256(pl).hexdigest(),"envelope":env})+"\n")
PY

# plankton: strip the signature from a stored record, leaving its id intact
python3 - <<'PY'
import json, glob
p = glob.glob("p/objects/sha256/*.json")[0]
o = json.load(open(p)); o["envelope"]["signatures"] = []
open(p,"w").write(json.dumps(o))
PY

# Count STRUCTURALLY, not by grepping the human output. The first version of this PoC grepped for
# "whenever-you-like" in `nekton about` and got 0 even against the vulnerable binary, because the
# prose form does not print `when` that way - it would have reported PREVENTED either way, which is
# precisely the corrupt-poisons-read defect this suite already carries once.
nclaims=$(nekton about "$H" --json 2>/dev/null | python3 -c "import json,sys;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 9)
nbad=$(( nclaims - 1 ))
pn=$(plankton records --json 2>/dev/null | python3 -c "import json,sys;print(len(json.load(sys.stdin)['records']))" 2>/dev/null || echo 9)

echo "nekton indexed the invalid-when claim: $nbad (want 0, of $nclaims total);  plankton kept the unsigned record: $pn (want 0)"
if [ "${nbad:-1}" = 0 ] && [ "${pn:-1}" = 0 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
