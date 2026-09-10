# Contributing

Thanks for your interest. kton is a small, dependency-free reference implementation of a
content-addressed provenance substrate (the `plankton` + `nekton` kernels and the `kton` cockpit).
Contributions are welcome; a few invariants are non-negotiable because they *are* the design.

## The invariants (CI enforces these)

1. **Documents, never executes.** No package imports `os/exec`. The substrate hashes,
   canonicalizes, verifies, compares, and indexes - it never runs protocols, normalisers, or
   candidate tools. Running things is an *executor's* job.
2. **Kernels stay WASM-clean.** The `plankton` and `nekton` kernels import no `net/http` and no I/O
   ports - they must compile to `GOOS=js GOARCH=wasm`. Serving, mirroring, pinning, and anchoring
   live in the `kton` cockpit.
3. **Dependency direction is one-way.** `nekton` may depend on `plankton`; `kton` conducts both and
   reimplements nothing (delete `kton` and every operation still runs directly). Never the reverse.
4. **Zero external dependencies.** The reference implementation is standard-library only. Please keep
   it that way; reach for a dependency only after discussion in an issue.

Run the guard locally before sending a change:

```sh
bash scripts/check-import-direction.sh
```

## Building and testing

The repo is a Go workspace (`go.work`) tying three modules, and the workspace root is **not itself a
module** - `go test ./...` from the root fails with *"directory prefix . does not contain modules
listed in go.work"*. Run the loop per module:

```sh
for m in reference nekton/reference kton/reference; do
  ( cd "$m" && go build ./... && go test ./... && go vet ./... )
done
gofmt -l reference nekton/reference kton/reference   # must print nothing
```

`reference/` is plankton, `nekton/reference/` is nekton, `kton/reference/` is the cockpit. CI runs
exactly this loop, plus the architecture and scope guards, the `js/wasm` builds, the frozen
conformance vectors and `security/check.sh`.

## Proposing changes

**Workflow.**

- **Cleanups** - typos, dead links, stale comments, formatting, doc-consistency fixes - go straight to
  `main`; no issue needed.
- **Code changes** and **spec changes** start from a GitHub **issue**, are developed on a **branch named
  for that issue** (`<issue-number>-<short-slug>`, e.g. `42-verify-all-signers`), and land via a **pull
  request** that references the issue. Every substantive change stays traceable to a stated rationale.

Beyond that:

- Open an issue first for anything touching the wire form, canonicalization, the action key, or the
  spec - these are the stability contract and change deliberately.
- Keep changes minimal and match the surrounding style.
- Content-addressed test vectors are the cross-implementation contract; if your change affects
  identity, regenerate them (`cd reference && go run ./testdata/gen`) and say so explicitly in the
  PR. CI fails if the committed vectors drift.

## Sign-off (DCO)

This project uses the [Developer Certificate of Origin](DCO). By contributing, you certify the DCO
for your contribution. Add a sign-off line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it for you (the name/email must match your `user.name`/`user.email`). We use
the DCO rather than a CLA - no copyright assignment, just the certification above.

**Contributing to the *specification* (not the code)** - the normative spec in [`spec/`](spec/) is
governed by the Community Specification framework in
[`community-specification/`](community-specification/): its license
([`01-community-specification-license-v1.md`](community-specification/01-community-specification-license-v1.md)),
scope ([`02-scope.md`](community-specification/02-scope.md)), governance, and contribution process
([`06-contributing.md`](community-specification/06-contributing.md)). Spec changes follow that process;
code changes follow this file.
