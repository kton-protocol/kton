#!/usr/bin/env bash
# nanopub-signed-eq-published: the RSA-signed quad set diverged from the published TriG; a tampered nanopub kept sig+Trusty-URI byte-identical. FIXED 1a8c798.
echo "nekton nanopublish then tamper a published triple -> re-derive-from-claim still accepted; FIXED 1a8c798 (publish exactly the signed quads)."
