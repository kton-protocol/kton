#!/usr/bin/env bash
# scope-path-traversal: a claim's `scope` is a free-form string in a SIGNED PAYLOAD, and the store
# derived a filename from it. `scope: "sha256:../../../tmp/x"` made nekton create and append to a
# file anywhere the process could write - and ingesting the SAME claim twice made rewriteSubnekton
# truncate that file to the attacker's record, destroying whatever else was in it.
#
# Reachable from a hostile peer: `kton mirror nekton <peer>` feeds peer envelopes straight to Add,
# and ingest does not verify signatures (SPEC §8), so any key will do.
#
# Same class as the blobstore path (fixed in #79) - validate before deriving a path - left standing
# in the store layout added by #41. FIXED #87: a scope must be a canonical content hash before it
# can name a file, and the result is proven to stay under the store root.
set -u
command -v nekton >/dev/null 2>&1 || { echo "VERDICT: N-A (no nekton on PATH)"; exit 0; }
W=$(mktemp -d) || { echo "VERDICT: N-A"; exit 0; }
cd "$W" || { echo "VERDICT: N-A"; exit 0; }

mkdir -p victim
printf 'line one\nline two\nline three\n' > victim/data.nekton.jsonl
export NEKTON_DIR="$W/reg"
nekton keygen k >/dev/null 2>&1
H="sha256:$(printf x | sha256sum | cut -d' ' -f1)"

# POSITIVE CONTROL. Everything below asserts that something did NOT happen - no file outside the
# store, the victim file untouched. A binary that never ran satisfies all of it. So first prove the
# binary works and that a claim of this exact shape, with a LEGITIMATE scope, does land in the
# store; only then does "the hostile one did not" mean anything.
printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"ok":"1"},"by":"a","when":"2026-07-16T00:00:00Z"}' \
  "$H" > control.json
nekton claim control.json k.key --add >/dev/null 2>&1
control=$(find "$W/reg/objects" -name '*.nekton.jsonl' -exec cat {} + 2>/dev/null | grep -c .)
if [ "${control:-0}" -lt 1 ]; then
  echo "setup failed: a benign claim did not reach the store either, so 'the attack wrote nothing' proves nothing"
  echo "VERDICT: INCONCLUSIVE"; exit 0
fi

# 1) escape: write outside the store
printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"x":"1"},"by":"a","when":"2026-07-16T00:00:00Z","scope":"sha256:../../../../%s/ESCAPED","prev":"%s"}' \
  "$H" "$(basename "$W")" "$H" > escape.json
nekton claim escape.json k.key --add >/dev/null 2>&1

# 2) destroy: point at an existing file and ingest twice, so the rewrite path truncates it
printf '{"subject":[{"hash":"%s"}],"predicate":"https://kton.dev/v/note","object":{"y":"2"},"by":"a","when":"2026-07-16T00:00:00Z","scope":"sha256:../victim/data","prev":"%s"}' \
  "$H" "$H" > destroy.json
nekton claim destroy.json k.key --add >/dev/null 2>&1
nekton claim destroy.json k.key --add >/dev/null 2>&1

escaped=0
ls "$W"/*.jsonl >/dev/null 2>&1 && escaped=1
[ -f "$W/reg/objects/scope/../ESCAPED.nekton.jsonl" ] && escaped=1
lines=$(grep -c . victim/data.nekton.jsonl 2>/dev/null || echo 0)

echo "wrote outside the store: $escaped (want 0);  victim file lines: $lines (want 3)"
if [ "$escaped" = 0 ] && [ "$lines" = 3 ]; then echo "VERDICT: PREVENTED"; else echo "VERDICT: VULNERABLE"; fi
