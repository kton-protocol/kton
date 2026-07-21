#!/usr/bin/env bash
# sigstore-sign-claim.sh - add a human's ACCOUNTABLE identity to a nekton claim, keyless.
#
# The protocol is signing-agnostic: a nekton claim is DSSE-signed (Ed25519, often an ephemeral
# throwaway key - anonymous by default). This adds the AUTHORITY layer: the publishing human signs
# the claim keyless via Sigstore, so "who stands behind it" becomes a verifiable OIDC identity
# (your GitHub / email), with NO long-lived key to distribute and a Rekor transparency-log witness.
# Neither kernel nor kton may spawn a process (CI guard: no os/exec), so this composition lives here.
#
#   cosign sign-blob <claim> --bundle <claim>.sigstore.json   → OIDC login → Fulcio cert → Rekor
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

echo "signing (keyless) - this opens a GitHub/OIDC login; approve as yourself:"
"$cosign" sign-blob "$claim" --bundle "$bundle" --yes

echo "signed → $bundle  (Fulcio cert + signature + Rekor entry, bound to your OIDC identity)"

if [[ -n "$verify_identity" ]]; then
  echo "verifying the bundle against identity: $verify_identity"
  "$cosign" verify-blob "$claim" --bundle "$bundle" \
    --certificate-identity-regexp "$verify_identity" \
    --certificate-oidc-issuer-regexp '.*'
fi
