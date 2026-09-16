#!/usr/bin/env bash
# Asserts WHICH BYTES sigstore-sign-claim.sh hands the signer.
#
# No OIDC, no network, no real cosign: a stub on --cosign records the file it was given. That is the
# right instrument for this property - the finding was "it signs the wrong artifact", and you prove
# that by capturing what gets signed, not by signing it for real. A live round-trip against real
# cosign is a separate, opt-in check (see --live below); it confirms the integration, not the binding.
#
#   bash scripts/sigstore-sign-claim_test.sh          # stub only (what CI runs)
#   bash scripts/sigstore-sign-claim_test.sh --live   # additionally: real cosign, real OIDC, real
#                                                     # Rekor entry - permanent and public
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
# PREREQUISITES first. The helper asks the kernel what canonical means, so without nekton every
# case fails - and the summary at the bottom would blame the helper for signing the wrong artifact
# when the truth is that nothing was checked. A check that cannot run says so.
missing=""
for t in nekton python3; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
if [ -n "$missing" ]; then
  echo "::error::cannot check the sigstore helper - missing:$missing"
  echo "::error::nekton is the authority on canonical form here; without it nothing below is evidence."
  exit 1
fi

fail=0
say() { printf '  %-52s %s\n' "$1" "$2"; }

# A claim whose payload is a real canonical Statement, and the SAME claim re-serialized: pretty
# printed, and with a second signature appended. The claim is identical in all three; only the
# envelope file differs.
python3 - "$W" <<'PY'
import base64, json, sys, hashlib
w = sys.argv[1]
stmt = {"_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://kton.dev/claim/v0",
        "subject": [{"uri": "urn:example:thing"}],
        "predicate": {"predicate": {"uri": "https://example.org/reviewed"},
                      "by": "CN=A", "when": "2026-07-16T00:00:00Z"}}
payload = json.dumps(stmt, separators=(',', ':'), sort_keys=True).encode()
b64 = base64.b64encode(payload).decode()
env = {"payloadType": "application/vnd.in-toto+json", "payload": b64,
       "signatures": [{"keyid": "aaaa", "sig": "c2ln"}]}
open(w + "/plain.dsse.json", "w").write(json.dumps(env, separators=(',', ':')))
open(w + "/pretty.dsse.json", "w").write(json.dumps(env, indent=2))       # reformatted
env2 = dict(env); env2["signatures"] = env["signatures"] + [{"keyid": "bbbb", "sig": "c2ln"}]
open(w + "/cosigned.dsse.json", "w").write(json.dumps(env2, indent=4))    # + a co-signature
# The PAYLOAD itself in a non-canonical spelling. A DSSE payload need not be canonical - the
# kernel canonicalizes when deriving the claim id - so this is a valid claim with the SAME id,
# and its bytes are not the ones the id is derived from. Varying only the envelope missed this.
pretty_payload = json.dumps(stmt, indent=2).encode()
envp = {"payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(pretty_payload).decode(),
        "signatures": [{"keyid": "aaaa", "sig": "c2ln"}]}
open(w + "/noncanonical-payload.dsse.json", "w").write(json.dumps(envp, separators=(",", ":")))
open(w + "/expected.sha256", "w").write(hashlib.sha256(payload).hexdigest())
PY

cat > "$W/cosign-stub" <<'STUB'
#!/usr/bin/env bash
# Records the sha256 of the file handed to sign-blob/verify-blob, then writes a dummy bundle.
for a in "$@"; do case "$a" in sign-blob|verify-blob) verb="$a";; esac; done
target=""; prev=""
for a in "$@"; do
  case "$prev" in --bundle) bundle="$a";; esac
  case "$a" in -*|sign-blob|verify-blob) ;; *) [ -z "$target" ] && target="$a";; esac
  prev="$a"
done
sha256sum "$target" | cut -d' ' -f1 >> "$SIGNED_LOG"
[ -n "${bundle:-}" ] && echo '{"stub":true}' > "$bundle"
exit 0
STUB
chmod +x "$W/cosign-stub"

expected=$(cat "$W/expected.sha256")
for form in plain pretty cosigned; do
  export SIGNED_LOG="$W/$form.log"; : > "$SIGNED_LOG"
  if ! bash "$HERE/sigstore-sign-claim.sh" "$W/$form.dsse.json" --cosign "$W/cosign-stub" \
        --bundle "$W/$form.sigstore.json" >/dev/null 2>&1; then
    say "$form" "SCRIPT FAILED"; fail=1; continue
  fi
  got=$(head -1 "$SIGNED_LOG")
  if [ "$got" = "$expected" ]; then
    say "$form envelope" "signed the canonical Statement bytes"
  else
    say "$form envelope" "SIGNED THE WRONG BYTES ($got, want $expected)"; fail=1
  fi
done

# The property in one line: three different envelope files, one signed artifact.
n=$(cat "$W"/*.log | sort -u | wc -l)
if [ "$n" = 1 ]; then
  say "across all three serializations" "one signed artifact - envelope form does not move it"
else
  say "across all three serializations" "$n DIFFERENT signed artifacts"; fail=1
fi

# A payload in a NON-CANONICAL spelling must not be signed in that spelling. It is a valid claim
# with the same id; its bytes are simply not the ones the id is derived from, and binding an
# external identity to them is the same defect one layer down.
export SIGNED_LOG="$W/noncanon.log"; : > "$SIGNED_LOG"
if bash "$HERE/sigstore-sign-claim.sh" "$W/noncanonical-payload.dsse.json" --cosign "$W/cosign-stub" \
      --bundle "$W/noncanon.sigstore.json" >/dev/null 2>&1; then
  got=$(head -1 "$SIGNED_LOG")
  if [ "$got" = "$expected" ]; then
    say "a non-canonical payload" "canonicalized before signing"
  else
    say "a non-canonical payload" "SIGNED THE STORED SPELLING ($got)"; fail=1
  fi
else
  say "a non-canonical payload" "refused"
fi

# A payload that is not an in-toto Statement must be refused rather than signed.
python3 -c "
import base64,json,sys
open('$W/bogus.dsse.json','w').write(json.dumps({'payloadType':'application/vnd.in-toto+json',
  'payload':base64.b64encode(b'{\"not\":\"a statement\"}').decode(),'signatures':[]}))"
export SIGNED_LOG="$W/bogus.log"; : > "$SIGNED_LOG"
if bash "$HERE/sigstore-sign-claim.sh" "$W/bogus.dsse.json" --cosign "$W/cosign-stub" \
      --bundle "$W/bogus.sigstore.json" >/dev/null 2>&1; then
  say "a payload that is not a Statement" "WAS SIGNED"; fail=1
else
  say "a payload that is not a Statement" "refused"
fi

if [ "${1:-}" = "--live" ]; then
  echo
  echo "LIVE: real cosign, real OIDC login, a PERMANENT PUBLIC Rekor entry under your identity."
  command -v cosign >/dev/null || { echo "  no cosign on PATH"; exit $fail; }
  bash "$HERE/sigstore-sign-claim.sh" "$W/plain.dsse.json" --bundle "$W/live.sigstore.json" || exit 1
  python3 -c "
import base64,json,hashlib
env=json.load(open('$W/plain.dsse.json'))
open('$W/stmt.json','wb').write(base64.b64decode(env['payload']))"
  echo "  verifying the bundle against the SAME bytes the script signed:"
  cosign verify-blob "$W/stmt.json" --bundle "$W/live.sigstore.json" \
    --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
    && echo "  live round-trip OK" || { echo "  live round-trip FAILED"; fail=1; }
fi

echo
[ "$fail" = 0 ] && echo "sigstore-sign-claim: PASS" || echo "::error::sigstore-sign-claim signs the wrong artifact"
exit $fail
