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

## Supported versions

Until a stable release, only the latest tag (currently the `v0.1.x` line) receives security fixes.
