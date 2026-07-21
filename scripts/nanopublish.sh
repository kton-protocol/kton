#!/usr/bin/env bash
# nanopublish.sh - the durable RSA/nanopublication edge for a signed nekton claim.
#
# The kernels (plankton, nekton) AND the kton cockpit deliberately CANNOT spawn a process
# (CI guard: no os/exec - "documents/conducts, never executes"). The reference nanopub tooling is
# an external signer, so the composition lives HERE, at the shell level, not inside any binary:
#
#   1. nekton export --nanopub <claim> --creator <orcid>   → our neutral RDF projection, carrying the
#        two soundness bindings (prov:wasDerivedFrom pk:<claimId>; pav:createdBy = the publisher).
#   2. np sign -k <rsa-key> -s <orcid>                      → RSA re-sign over the normalized RDF +
#        Trusty URI + npx:hasPublicKey → a network-verifiable, permanent nanopublication.
#
# The DSSE/Ed25519 record stays the internal, Sigstore-aligned truth (verify with `nekton verify`,
# witness with `kton anchor`); this is the permanent, log-independent projection for citation.
#
# Requires: `nekton` on PATH; `java` + the nanopub-java jar (via --jar or $NANOPUB_JAR).
set -euo pipefail

claim=""; creator=""; key="${HOME}/.nanopub/id_rsa"; jar="${NANOPUB_JAR:-}"; out=""; publish=0
usage() {
  echo "usage: nanopublish.sh <claim.dsse.json> --creator <orcid-iri> [--key <rsa-key>] [--jar <nanopub.jar>] [-o out.trig] [--publish]" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --creator) creator="$2"; shift 2 ;;
    --key)     key="$2"; shift 2 ;;
    --jar)     jar="$2"; shift 2 ;;
    -o)        out="$2"; shift 2 ;;
    --publish) publish=1; shift ;;
    -*)        echo "unknown flag: $1" >&2; usage ;;
    *)         claim="$1"; shift ;;
  esac
done
[[ -n "$claim" && -n "$creator" ]] || usage
[[ -n "$jar" ]] || { echo "error: need the nanopub-java jar (--jar or \$NANOPUB_JAR)" >&2; exit 2; }
[[ -f "$key" ]] || { echo "error: RSA key not found: $key (make one with: java -jar \"$jar\" mkkeys)" >&2; exit 2; }
[[ -n "$out" ]] || out="${claim%.dsse.json}.np.trig"

tmp="$(mktemp --suffix=.trig)"; trap 'rm -f "$tmp"' EXIT

# 1. render our nanopub RDF with the soundness bindings (creator = the signer, so signer == creator)
nekton export --nanopub "$claim" --creator "$creator" -o "$tmp"

# 2. RSA re-sign + Trusty URI via the reference tooling (composed here, never spawned by a binary)
java -jar "$jar" sign "$tmp" -k "$key" -s "$creator" -o "$out"

trusty="$(grep -oE '@prefix this: <[^>]+>' "$out" | head -1 | sed -E 's/@prefix this: <(.*)>/\1/')"
echo "nanopublished: $out"
echo "  trusty URI:   $trusty"
echo "  signer/creator: $creator"

if [[ "$publish" -eq 1 ]]; then
  java -jar "$jar" publish "$out"
fi
