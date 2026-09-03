# Federation conformance fixtures (SPEC §12)

The answers a §12 query must produce, as bytes. §12 fixes the **queries and the wire form**; how
they are carried is an implementation choice (Annex C describes one HTTP binding).

These exist because the reference implementation ships a federation **client and no server** (#83).
A client tested against its own server proves only that the two agree with each other; tested
against a fixed document it proves it implements the format. A second implementation can serve
these and a third can consume them.

| file | the query it answers |
|---|---|
| `sync-plankton.json` | `sync(0)` over a registry holding one foton |

Generated from a real registry with a seeded key, so the envelope is genuinely signed and its
`fotonId` is genuinely the content address of its covered projection — not a hand-written shape that
happens to parse.
