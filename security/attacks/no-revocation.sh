#!/usr/bin/env bash
# no-revocation (OPEN): kton has no key-revocation notion; a revoked keys signatures verify as authoritative forever.
echo "OPEN: no revocation mechanism. See findings/key-lifecycle-design-scope.md — revocation as an additive signed claim + a time-aware trust filter keyed on anchor integratedTime."
