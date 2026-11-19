#!/usr/bin/env bash
# seed-unregistered-fallback: the write registry (#248) reads only the scope files a write touches,
# and steps aside to a full Open (ErrNeedsFullOpen) when it meets a record .seq does not number - the
# state a git merge of the store leaves. As first proposed it could step aside AFTER storing a new seed
# and BEFORE registering it in the root. The full-Open retry re-signed the same seed, found it present
# (IsNew false) and skipped the registration: the seed was stored, never listed in the root, and the
# CLI said "already present" with exit 0.
#
# FIXED (#269 review W1): every scope file the write touches is loaded before anything is stored, and
# a seed the store holds but its root does not list is registered, new or not.
set -u
for t in nekton python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "VERDICT: N-A (no $t on PATH)"; exit 0; }
done
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }
nekton keygen a >/dev/null 2>&1
spec() { printf '{"subject":[{"uri":"%s"}],"predicate":"https://kton.dev/v/x","by":"a","when":"2026-11-19T10:00:0%sZ"}' "$1" "$2"; }
nekton init --sign a.key --registry A >/dev/null 2>&1
spec urn:x:1 1 > s1.json; nekton claim s1.json a.key --add --registry A >/dev/null 2>&1
cp -r A B
spec urn:x:2 2 > s2.json; nekton claim s2.json a.key --add --registry B >/dev/null 2>&1
f=$(cd A/objects/scope 2>/dev/null && ls *.nekton.jsonl 2>/dev/null | head -1)
[ -n "$f" ] && [ -s "B/objects/scope/$f" ] || { echo "setup failed: no root scope file"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
# a git merge of the two copies: A's root file gains B's line, A's .seq does not number it
cat "B/objects/scope/$f" "A/objects/scope/$f" | sort -u > merged; cp merged "A/objects/scope/$f"

out=$(nekton seed child --sign a.key --add --registry A --when 2026-11-19T10:00:05Z 2>&1); rc=$?
reg=$(NEKTON_DIR=A nekton verify --root --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("registered"))' 2>/dev/null)
[ -n "$reg" ] && [ "$reg" != None ] || { echo "setup failed: verify --root unreadable"; echo "VERDICT: INCONCLUSIVE"; exit 0; }
said_present=0; echo "$out" | grep -q "already present" && said_present=1
echo "seed write exit $rc; reported 'already present' for a new seed: $said_present (want 0); subnektons the root registers: $reg (want 1)"
if [ "$rc" = 0 ] && [ "$said_present" = 0 ] && [ "$reg" = 1 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
