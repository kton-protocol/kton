# Licenses

*This is the `License.md` the Community Specification process asks a Working Group to deploy. It
states what this repository actually ships; the authoritative prose is the License section of
[`README.md`](README.md), and this file must not disagree with it.*

Three regimes, by artifact type - a specification and its reference code have different licensing
needs.

## Specification License

The normative specification (`spec/`) is subject to the **Community Specification License 1.0**,
available at [https://github.com/CommunitySpecification/1.0](https://github.com/CommunitySpecification/1.0)
and reproduced unmodified at
[`community-specification/01-community-specification-license-v1.md`](community-specification/01-community-specification-license-v1.md).
It grants *independent implementers* the copyright and patent terms a standard requires, which an
open-source or CC-BY license does not.

The patent commitment it establishes is bounded by [`Scope.md`](Scope.md).

## Source Code License

All Go sources under `reference/`, `nekton/` and `kton/` are subject to the **Apache License 2.0**
([`LICENSE`](LICENSE)). Its patent grant covers *this* implementation.

> The Community Specification template ships this file designating **MIT** as the default source
> code license. That default does not describe this repository and has been corrected: the reference
> implementation is Apache-2.0, and a deployed `License.md` saying otherwise would tell a reader the
> opposite of what the code carries.

## Documentation License

Other, non-normative prose - documentation, man pages, design notes - is under **CC BY 4.0**
([`LICENSE-CC-BY-4.0.txt`](LICENSE-CC-BY-4.0.txt)).

## Conflicts

In the case of any conflict or confusion within this specification repository between the Community
Specification License and a designated source code license, the terms of the Community Specification
License shall apply.

Copyright (c) 2026 Michael Hackl.
