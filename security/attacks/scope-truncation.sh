#!/usr/bin/env bash
# scope-truncation: a withheld TAIL claim silently truncates a sealed scope; nekton head cannot detect it in-band. CAVEATED 8bbdf54 (boundary).
echo "seal a scope, withhold the tail claim -> nekton head reports a stale tip; in-band undetectable (monotone/additive design). Defense: pinned/anchored head. Caveated 8bbdf54."
