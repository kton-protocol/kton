#!/usr/bin/env bash
# CI guard for the layered architecture (docs/decisions.md §2, issue #2):
#
#   kton -> {plankton, nekton}      (cockpit conducts both)
#   nekton -> plankton              (commitments about reproducible results)
#   plankton -> (nothing)           (the clean kernel)
#
# and the invariant that THE KERNELS OPEN NO SOCKET: neither may import net/http, bare net, or
# crypto/tls. Reaching an address is a transport and belongs to a cockpit; a hash says WHAT, an
# address says WHERE, and the kernels work from hashes (#104). This is also what keeps them
# WASM-compilable. Fails the build if any edge points the wrong way.
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

# The kernels open no socket. net/http alone was not enough: bare `net` dials one directly and
# crypto/tls wraps one, so a kernel could have grown a network dependency with this guard green.
# (Match the import path only, not prose comments.)
for mod in reference nekton/reference; do
  for pkg in '"net/http"' '"net"' '"crypto/tls"' '"net/url"'; do
    check "${mod} imports no ${pkg} (the kernels open no socket, and stay WASM-clean)" "$pkg" "$ROOT/$mod"
  done
done

# The cockpit MAY reach an address - that is what it is for - but each file that does is named here,
# so growing the network surface is a deliberate act visible in a diff rather than a side effect.
expected_net='cmd/kton/fetch.go sigstore/rekor.go'
actual_net="$(cd "$ROOT/kton/reference" && grep -rln --include='*.go' -e '"net/http"' -e '"crypto/tls"' . \
  | sed 's|^\./||' | grep -v '_test\.go$' | sort | tr '\n' ' ' | sed 's/ $//')"
if [[ "$actual_net" == "$expected_net" ]]; then
  echo "ok: kton reaches the network from exactly the files on record ($expected_net)"
else
  echo "FAIL: the cockpit's network surface changed" >&2
  echo "  on record: $expected_net" >&2
  echo "  actual:    $actual_net" >&2
  echo "  If this is intended, update expected_net in $0 in the same commit." >&2
  fail=1
fi

# "documents, never executes" - no kernel (or cockpit) may spawn a process. Executors are
# separate programs; plankton/nekton/kton only hash, canonicalize, verify, compare, index, serve.
check 'plankton imports no os/exec (documents, never executes)' '"os/exec"' "$ROOT/reference"
check 'nekton imports no os/exec (documents, never executes)'   '"os/exec"' "$ROOT/nekton/reference"
check 'kton imports no os/exec (conducts, never executes)'      '"os/exec"' "$ROOT/kton/reference"

exit $fail
