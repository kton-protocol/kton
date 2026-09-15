# Security Policy

plankton, nekton, and kton are a **verification** substrate: the kernels *document, never execute*
(no `os/exec`; the kernels import no `net/http`). The threat model is therefore about the **integrity
of verification** - canonicalization, hashing, signature checking, and chain verification - not about
sandboxing executed code. Getting those wrong is what "a vulnerability" means here.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not as a public issue:

- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on the
  `kton-protocol/kton` repository.

Include a description, affected component (`plankton` / `nekton` / `kton`), and a minimal
reproduction (ideally a canonical-JSON / DSSE / foton-id vector). We aim to acknowledge within a few
working days.

Examples of in-scope issues:

- A canonicalization or hashing discrepancy that lets two different payloads share a foton id,
  action key, or `scope_id`.
- A signature-verification bypass (accepting a DSSE envelope under the wrong key, or a tampered
  payload verifying as valid).
- A scope/seed chain that verifies despite a broken or forged link.
- A `located-at` resolver (`kton fetch`) accepting content whose hash does not match the request.

Out of scope: anything requiring code the substrate never runs (it does not execute protocols,
normalisers, or candidate tools - that is an executor's concern), and denial-of-service from
maliciously large inputs to the cockpit.

## Known open issues

Stated here rather than left for a reporter to rediscover. Both come from an external review of the
development branch.

- **A claim can lose a signature when one statement arrives in two serializations.** Same canonical
  claim id, different literal signed bytes; the second arrival is misread as a duplicate and its
  signature is dropped, order-dependently. Loss of signing evidence, not forgery. Details and the
  reproduction are in `CHANGELOG.md` under 0.2.0.

- **`kton fetch` can be steered to a local address by DNS rebinding.** `checkDestination` resolves
  the hostname with `net.LookupIP`, then hands the URL to an `http.Client` that resolves it again on
  its own — so the address checked is not necessarily the address contacted, and `--allow-local` can
  be bypassed by a resolver that answers differently the second time. The redirect handler re-checks
  the host the same way and inherits the same gap. *(The reviewer reproduced this against a mock
  resolver and a loopback server; what is verified here is the code path, not a live exploit.)*

  This is the cockpit, not a kernel: the kernels open no socket at all. `kton fetch` moves to the
  cockpit repository with #103 and the fix belongs there — bind the checked address, by resolving
  once and dialling that address through a custom `DialContext`. Until then, do not point
  `kton fetch` at hostnames you do not control from a host whose local network matters.

## Supported versions

Until a stable release, only the latest tag (currently the `v0.1.x` line) receives security fixes.
