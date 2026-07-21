#!/usr/bin/env bash
# backdated-production (OPEN): a compromised key can backdate self-asserted when to produce records dated before compromise.
echo "OPEN: when is self-asserted; a compromised key backdates it. Fix (design): authoritative time = Rekor anchor integratedTime, not when. See key-lifecycle-design-scope.md."
