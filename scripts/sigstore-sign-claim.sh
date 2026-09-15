#!/usr/bin/env bash
# sigstore-sign-claim.sh - add a human's ACCOUNTABLE identity to a nekton claim, keyless.
#
# The protocol is signing-agnostic: a nekton claim is DSSE-signed (Ed25519, often an ephemeral
# throwaway key - anonymous by default). This adds the AUTHORITY layer: the publishing human signs
# the claim keyless via Sigstore, so "who stands behind it" becomes a verifiable OIDC identity
# (your GitHub / email), with NO long-lived key to distribute and a Rekor transparency-log witness.
# Neither kernel nor kton may spawn a process (CI guard: no os/exec), so this composition lives here.
#
#   cosign sign-blob <the claim's canonical Statement bytes> --bundle <claim>.sigstore.json
#       → OIDC login → Fulcio cert → Rekor
#
# Requires: `cosign` (via --cosign or $COSIGN, else `cosign` on PATH). Running it opens an OIDC flow
# (a URL / browser) where YOU authenticate as yourself - an agent cannot do this for you.
set -euo pipefail

claim=""; cosign="${COSIGN:-cosign}"; bundle=""; verify_identity=""
usage() {
  echo "usage: sigstore-sign-claim.sh <claim.dsse.json> [--cosign <path>] [--bundle <out>] [--verify-identity <email-or-regexp>]" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cosign)          cosign="$2"; shift 2 ;;
    --bundle)          bundle="$2"; shift 2 ;;
    --verify-identity) verify_identity="$2"; shift 2 ;;
    -*) echo "unknown flag: $1" >&2; usage ;;
    *)  claim="$1"; shift ;;
  esac
done
[[ -n "$claim" && -f "$claim" ]] || usage
[[ -n "$bundle" ]] || bundle="${claim%.dsse.json}.sigstore.json"

# SIGN THE STATEMENT BYTES, NOT THE ENVELOPE FILE.
#
# SPEC §8.1: "a scheme that signs bytes MUST sign the canonical Statement bytes, which are exactly
# the envelope's `payload`. It MUST NOT rest on a filename, on a particular serialization of the
# envelope, or on co-location."
#
# Handing cosign the whole .dsse.json binds the signature to one serialization of the envelope:
# re-indenting the file, or adding a co-signature to the signatures array, changes the signed
# artifact while the claim itself is unchanged - and the bundle then cannot be consumed as material
# ABOUT that claim without also preserving and interpreting that particular file.
#
# The payload is base64 of the canonical Statement. Decode it to a temp file and sign THAT, so the
# signed bytes are the same bytes the claim id is computed over, whatever the envelope looks like.
payload_b64=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["payload"])' "$claim") || {
  echo "cannot read a DSSE payload from $claim - is it an envelope?" >&2; exit 1; }
stmt=$(mktemp -t kton-statement.XXXXXX.json)
trap 'rm -f "$stmt"' EXIT
python3 -c 'import base64,sys; open(sys.argv[2],"wb").write(base64.b64decode(sys.argv[1]))' \
  "$payload_b64" "$stmt"
# It must BE the canonical statement, not merely decode to one.
#
# A DSSE payload is not required to be canonical: the kernel canonicalizes it when deriving the claim
# id, so an envelope whose payload is pretty-printed is a valid, genuinely signed claim with the same
# id as its compact twin. Signing those bytes unchanged would hand the external scheme a different
# artifact for each serialization - the same defect one layer down from the one this script fixes,
# and invisible because both calls succeed.
#
# It is REFUSED rather than canonicalized, deliberately. Signing canon(payload) would leave the
# Sigstore bundle standing over different bytes than the envelope's own DSSE signatures, so a
# verifier holding the envelope would have to know to canonicalize before checking the bundle - one
# claim, two signatures, two artifacts. Refusing keeps both over the same bytes. Re-author the claim
# through the kernel, which always emits canonical, and sign that.
#
# The test uses the kernel as the authority rather than reimplementing JCS here: a claim id IS
# sha256(canon(payload)), so a payload whose own sha256 equals the claim id is canonical, and one
# whose does not, is not.
nekton_bin="${NEKTON:-nekton}"
command -v "$nekton_bin" >/dev/null 2>&1 || {
  echo "need \`nekton\` on PATH (or \$NEKTON): the canonical form is the kernel's to decide, and" >&2
  echo "  reimplementing JCS in this script is how the two would come to disagree." >&2
  exit 1; }
claim_id=$("$nekton_bin" show "$claim" --json 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("claimId",""))' 2>/dev/null)
[[ -n "$claim_id" ]] || { echo "cannot read a claim id from $claim - is it a nekton claim?" >&2; exit 1; }
payload_sha="sha256:$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$stmt")"
if [[ "$payload_sha" != "$claim_id" ]]; then
  echo "refusing: this envelope's payload is not in canonical form." >&2
  echo "  claim id (sha256 of the CANONICAL statement): $claim_id" >&2
  echo "  sha256 of the payload as stored:              $payload_sha" >&2
  echo "  Signing the stored spelling would bind the external identity to bytes that are not the" >&2
  echo "  ones this claim is addressed by (SPEC §8.1). Re-author the claim with \`nekton claim\`," >&2
  echo "  which emits canonical bytes, and sign that." >&2
  exit 1
fi
python3 - "$stmt" <<'PYCHK' || exit 1
import json,sys
try: st=json.loads(open(sys.argv[1],'rb').read())
except Exception as e: print("decoded payload is not JSON: %s"%e, file=sys.stderr); sys.exit(1)
if st.get("_type") != "https://in-toto.io/Statement/v1":
    print("decoded payload is not an in-toto Statement", file=sys.stderr); sys.exit(1)
PYCHK

echo "signing (keyless) - this opens a GitHub/OIDC login; approve as yourself:"
echo "  signing the canonical Statement bytes ($(wc -c < "$stmt") bytes), not $claim"
"$cosign" sign-blob "$stmt" --bundle "$bundle" --yes

echo "signed → $bundle  (Fulcio cert + signature + Rekor entry, bound to your OIDC identity)"
echo "  attach it to the record with: nekton attach <claim-id> --scheme sigstore-bundle --file $bundle"

if [[ -n "$verify_identity" ]]; then
  echo "verifying the bundle against identity: $verify_identity"
  "$cosign" verify-blob "$stmt" --bundle "$bundle" \
    --certificate-identity-regexp "$verify_identity" \
    --certificate-oidc-issuer-regexp '.*'
fi
