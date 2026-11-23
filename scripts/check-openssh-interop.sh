#!/usr/bin/env bash
# kton-review A2 on #277: keys we write are read by ssh-keygen. (The other direction, keys made by
# ssh-keygen loading with the same seed, is in reference/keys/keys_test.go on checked-in fixtures.)
# ssh-keygen is run here, not from a Go test: the kernels start no process (check-import-direction).
#
#   1. reference/keys writes keys at bcrypt rounds 1, 16 and 64; ssh-keygen -y -P must print the
#      public key we wrote beside each.
#   2. plankton keygen --encrypt, end to end: ssh-keygen -y -P must print the key in its .pub.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v ssh-keygen >/dev/null || { echo "FAIL: ssh-keygen not found" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass='correct horse'
fail=0

( cd "$ROOT/reference" && KTON_KEYS_INTEROP_DIR="$work" go test -count=1 -run '^TestWriteInteropKeys$' ./keys >/dev/null )
for k in "$work"/kton-r*.key; do
  got="$(ssh-keygen -y -P "$pass" -f "$k" | cut -d' ' -f1,2)"
  want="$(cut -d' ' -f1,2 "$k.pub")"
  if [[ "$got" == "$want" ]]; then
    echo "ok: ssh-keygen reads $(basename "$k")"
  else
    echo "FAIL: ssh-keygen read $(basename "$k") as '$got', want '$want'" >&2
    fail=1
  fi
done

( cd "$ROOT/reference" && go build -o "$work/plankton" ./cmd/plankton )
KTON_KEY_PASSPHRASE="$pass" "$work/plankton" keygen "$work/cli" --encrypt >/dev/null
line="$(ssh-keygen -y -P "$pass" -f "$work/cli.key")"
got="$(echo "$line" | cut -d' ' -f2 | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n')"
want="$(tr -d ' \n' <"$work/cli.pub")"
if [[ "$got" == "$want" ]]; then
  echo "ok: ssh-keygen reads what plankton keygen --encrypt wrote (same public key as its .pub)"
else
  echo "FAIL: plankton keygen --encrypt: ssh-keygen gives $got, the .pub says $want" >&2
  fail=1
fi
if ssh-keygen -y -P "wrong" -f "$work/cli.key" >/dev/null 2>&1; then
  echo "FAIL: ssh-keygen accepted a wrong passphrase" >&2
  fail=1
fi
exit $fail
