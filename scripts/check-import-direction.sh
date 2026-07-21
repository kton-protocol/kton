#!/usr/bin/env bash
# CI guard for the layered architecture (DECISIONS §2, issue #2):
#
#   kton -> {plankton, nekton}      (cockpit conducts both)
#   nekton -> plankton              (commitments about reproducible results)
#   plankton -> (nothing)           (the clean kernel)
#
# and the WASM-cleanliness invariant: neither KERNEL may import net/http (ports/network live
# only in the kton cockpit). Fails the build if any edge points the wrong way.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

check() { # <label> <grep-pattern> <dir>
  local label="$1" pat="$2" dir="$3"
  local hits
  hits="$(grep -rn --include='*.go' "$pat" "$dir" || true)"
  if [[ -n "$hits" ]]; then
    echo "FAIL: $label" >&2
    echo "$hits" >&2
    fail=1
  else
    echo "ok: $label"
  fi
}

# Dependency direction - the kernels never depend upward.
check "plankton kernel imports no nekton (direction nekton -> plankton)" 'kton.dev/nekton' "$ROOT/reference"
check "plankton kernel imports no kton (nothing depends on the cockpit)"  'kton.dev/kton'   "$ROOT/reference"
check "nekton kernel imports no kton (nothing depends on the cockpit)"    'kton.dev/kton'   "$ROOT/nekton/reference"

# WASM cleanliness - kernels open no ports. (Match the import path only, not prose comments.)
check 'plankton kernel imports no net/http (WASM-clean, no ports)' '"net/http"' "$ROOT/reference"
check 'nekton kernel imports no net/http (WASM-clean, no ports)'   '"net/http"' "$ROOT/nekton/reference"

# "documents, never executes" - no kernel (or cockpit) may spawn a process. Executors are
# separate programs; plankton/nekton/kton only hash, canonicalize, verify, compare, index, serve.
check 'plankton imports no os/exec (documents, never executes)' '"os/exec"' "$ROOT/reference"
check 'nekton imports no os/exec (documents, never executes)'   '"os/exec"' "$ROOT/nekton/reference"
check 'kton imports no os/exec (conducts, never executes)'      '"os/exec"' "$ROOT/kton/reference"

exit $fail
