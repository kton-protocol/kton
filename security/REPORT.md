# kton red-team — findings report

*Originally rendered from 28 attack records in the signed kton graph. The renderer
(`provenance/render_report.py`), the signed claims and `keys/` are NOT in this repository, so this
file cannot be regenerated or verified from here and is maintained by hand. Until the graph is
published, read it as prose - the executable part of this suite is `check.sh`, which prints how
much of the engagement it actually runs.*

## Posture: **25/27 spectrum members fulfilled** → NOT SECURE (2 open)

25 closed · 2 open · 2 accepted boundary. Each attack was recorded as a signed `plankton` foton pinning its PoC (`attacks/<id>.sh`), with theory and
vulnerable/fixed commits as signed `nekton` claims. Those claims and the `keys/` directory are not in this
repository, so `nekton verify` cannot be run against them from here - `redteam.pub` alone verifies nothing.
10 of the 28 PoCs are executable and run in `check.sh`; the rest are records, not reproductions.

## By vulnerability class
| class | count |
|---|---|
| `viewer-trusts-declared-id` | 3 |
| `render-face-doesnt-escape` | 3 |
| `export-trusts-claimed-keyid` | 2 |
| `backstop-looks-up-not-reexecute` | 2 |
| `gate-trusts-mutable-graph-edge` | 2 |
| `no-key-lifecycle` | 2 |
| `read-face-trusts-declared-id` | 1 |
| `gate-trusts-recorded-tally` | 1 |
| `read-face-silent-partial` | 1 |
| `kernel-boundary-by-design` | 1 |
| `witness-not-bound-to-record` | 1 |
| `concurrency-nonatomic` | 1 |
| `freshness-monotone-boundary` | 1 |
| `closed-world-boundary` | 1 |
| `unvalidated-timestamp` | 1 |
| `spectrum-no-existence-check` | 1 |
| `federation-not-order-independent` | 1 |
| `canonicalization` | 1 |
| `read-face-brittle` | 1 |
| `witness-not-fully-verified` | 1 |

The recurring class: **a face or backstop trusts recorded/declared data instead of re-verifying the signed bytes / re-executing in a trusted executor.**

## Closed (fixed — reproduction now fails)
| id | sev | class | vulnerable @ | fixed @ |
|---|---|---|---|---|
| `anchor-bind` | RED | `witness-not-bound-to-record` | [`a687723`](https://github.com/gitmick/plankton/commit/a687723) | [`b92c3b3`](https://github.com/gitmick/plankton/commit/b92c3b3) |
| `anchor-checkpoint` | ORANGE | `witness-not-fully-verified` | [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938) | [`9cb7090`](https://github.com/gitmick/plankton/commit/9cb7090) |
| `attribution-siblings` | RED | `export-trusts-claimed-keyid` | [`24dfc6b`](https://github.com/gitmick/plankton/commit/24dfc6b) | [`fc77c28`](https://github.com/gitmick/plankton/commit/fc77c28) |
| `canon-bigint` | RED | `canonicalization` | [`24dfc6b`](https://github.com/gitmick/plankton/commit/24dfc6b) | [`1e667f3`](https://github.com/gitmick/plankton/commit/1e667f3) |
| `co-signer-drop` | ORANGE | `federation-not-order-independent` | [`0aa44b8`](https://github.com/gitmick/plankton/commit/0aa44b8) | [`b625b1f`](https://github.com/gitmick/plankton/commit/b625b1f) |
| `concurrency-races` | ORANGE | `concurrency-nonatomic` | [`a687723`](https://github.com/gitmick/plankton/commit/a687723) | [`af3cefa`](https://github.com/gitmick/plankton/commit/af3cefa) |
| `corrupt-poisons-read` | ORANGE | `read-face-brittle` | [`ed7a008`](https://github.com/gitmick/plankton/commit/ed7a008) | [`056b87a`](https://github.com/gitmick/plankton/commit/056b87a) |
| `envtally-CF2` | RED | `gate-trusts-recorded-tally` | [`3619db4`](https://github.com/gitmick/kton-examples/commit/3619db4) | [`0f3dafa`](https://github.com/gitmick/kton-examples/commit/0f3dafa) |
| `export-attribution` | RED | `export-trusts-claimed-keyid` | [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938) | [`e92beca`](https://github.com/gitmick/plankton/commit/e92beca) |
| `fourEyes-graphpoll` | RED | `gate-trusts-mutable-graph-edge` | [`ac188cb`](https://github.com/gitmick/kton-examples/commit/ac188cb) | [`4931c42`](https://github.com/gitmick/kton-examples/commit/4931c42) |
| `fourEyes-max` | RED | `gate-trusts-mutable-graph-edge` | [`b2616d7`](https://github.com/gitmick/kton-examples/commit/b2616d7) | [`56ae3cd`](https://github.com/gitmick/kton-examples/commit/56ae3cd) |
| `nanopub-signed-eq-published` | RED | `render-face-doesnt-escape` | [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938) | [`1a8c798`](https://github.com/gitmick/plankton/commit/1a8c798) |
| `normalizer-forge` | RED | `backstop-looks-up-not-reexecute` | [`2024ca5`](https://github.com/gitmick/kton-examples/commit/2024ca5) | [`dee089c`](https://github.com/gitmick/kton-examples/commit/dee089c) |
| `rdf-injection` | RED | `render-face-doesnt-escape` | [`2e896c8`](https://github.com/gitmick/plankton/commit/2e896c8) | [`804f052`](https://github.com/gitmick/plankton/commit/804f052) |
| `scope-truncation` | ORANGE | `freshness-monotone-boundary` | [`a687723`](https://github.com/gitmick/plankton/commit/a687723) | [`8bbdf54`](https://github.com/gitmick/plankton/commit/8bbdf54) |
| `screenshot-viewer-labels` | RED | `viewer-trusts-declared-id` | [`46ed3fa`](https://github.com/gitmick/kton-examples/commit/46ed3fa) | [`b2616d7`](https://github.com/gitmick/kton-examples/commit/b2616d7) |
| `silent-source-drop` | ORANGE | `read-face-silent-partial` | [`ed7a008`](https://github.com/gitmick/plankton/commit/ed7a008) | [`056b87a`](https://github.com/gitmick/plankton/commit/056b87a) |
| `spectrum-existence` | ORANGE | `spectrum-no-existence-check` | [`7df1e70`](https://github.com/gitmick/plankton/commit/7df1e70) | [`05a94d8`](https://github.com/gitmick/plankton/commit/05a94d8) |
| `spectrum-launder` | RED | `backstop-looks-up-not-reexecute` | [`24bd5af`](https://github.com/gitmick/kton-examples/commit/24bd5af) | [`46ed3fa`](https://github.com/gitmick/kton-examples/commit/46ed3fa) |
| `suppress-replay` | RED | `read-face-trusts-declared-id` | [`7df1e70`](https://github.com/gitmick/plankton/commit/7df1e70) | [`d0f7cf9`](https://github.com/gitmick/plankton/commit/d0f7cf9) |
| `viewer-selfsigned` | RED | `viewer-trusts-declared-id` | [`b8a642a`](https://github.com/gitmick/kton-examples/commit/b8a642a) | [`f5570c0`](https://github.com/gitmick/kton-examples/commit/f5570c0) |
| `viewer-xss` | RED | `render-face-doesnt-escape` | [`826ea7d`](https://github.com/gitmick/kton-examples/commit/826ea7d) | [`b8a642a`](https://github.com/gitmick/kton-examples/commit/b8a642a) |
| `wasm-viewer-trust` | RED | `viewer-trusts-declared-id` | [`804f052`](https://github.com/gitmick/plankton/commit/804f052) | [`6ff639e`](https://github.com/gitmick/plankton/commit/6ff639e) |
| `when-unvalidated` | ORANGE | `unvalidated-timestamp` | [`e5c01e2`](https://github.com/gitmick/plankton/commit/e5c01e2) | [`e8da93c`](https://github.com/gitmick/plankton/commit/e8da93c) |

## Open (still exploitable)
| id | sev | class | vulnerable @ | fix / theory |
|---|---|---|---|---|
| `backdated-production` | RED | `no-key-lifecycle` | [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea) | **OPEN** — A compromised key backdates the self-asserted when to 'produce' record |
| `no-revocation` | RED | `no-key-lifecycle` | [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea) | **OPEN** — kton has no revocation/validity notion: a revoked or compromised key's |

## Accepted boundaries (irreducible — a truthful caveat is the correct response)
- **`author-records-unverified`** — plankton author records hash(--out) and the --cmd string; it NEVER runs the command (SPEC 5: the kernel MUST NOT execute). Trust that a computation is honest belongs to a trusted executor / re-run. Not a kernel defect.
- **`federation-withholding`** — A verifier sees only the sources it names; a withheld source (or revocation) removes nothing it should. Documented closed-world limit: a verdict must NAME the sources it consulted; withholding has leverage only at the closed-world gate.

## Detail (theory + reproduction)
### `anchor-bind` — RED · ✅ closed
- **class:** `witness-not-bound-to-record`
- **theory:** kton anchor never checked the returned Rekor entry was about the submitted record; a replayed unrelated entry verified as an 'independent witness'. Fixed by binding the entry to the envelope.
- **vulnerable at:** pk [`a687723`](https://github.com/gitmick/plankton/commit/a687723)
- **fixed at (reproduction now fails):** pk [`b92c3b3`](https://github.com/gitmick/plankton/commit/b92c3b3)
- **PoC:** [`attacks/anchor-bind.sh`](attacks/anchor-bind.sh)

### `anchor-checkpoint` — ORANGE · ✅ closed
- **class:** `witness-not-fully-verified`
- **theory:** A custom Rekor endpoint with a self-served key could fabricate an entry. Fixed: verify the Rekor SET against a PINNED key (verifying the signed tree-head checkpoint is a further hardening).
- **vulnerable at:** pk [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938)
- **fixed at (reproduction now fails):** pk [`9cb7090`](https://github.com/gitmick/plankton/commit/9cb7090)
- **PoC:** [`attacks/anchor-checkpoint.sh`](attacks/anchor-checkpoint.sh)

### `attribution-siblings` — RED · ✅ closed
- **class:** `export-trusts-claimed-keyid`
- **theory:** The verified-signer fix covered export --rdf but nekton export JSON / nanopublish / by-about still stamped the unverified keyid. Fixed across the nekton faces.
- **vulnerable at:** pk [`24dfc6b`](https://github.com/gitmick/plankton/commit/24dfc6b)
- **fixed at (reproduction now fails):** pk [`fc77c28`](https://github.com/gitmick/plankton/commit/fc77c28)
- **PoC:** [`attacks/attribution-siblings.sh`](attacks/attribution-siblings.sh)

### `author-records-unverified` — YELLOW · ⚪ boundary
- **class:** `kernel-boundary-by-design`
- **theory:** plankton author records hash(--out) and the --cmd string; it NEVER runs the command (SPEC 5: the kernel MUST NOT execute). Trust that a computation is honest belongs to a trusted executor / re-run. Not a kernel defect.
- **vulnerable at:** pk [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea)
- **PoC:** [`attacks/author-records-unverified.sh`](attacks/author-records-unverified.sh)

### `backdated-production` — RED · 🔴 OPEN
- **class:** `no-key-lifecycle`
- **theory:** A compromised key backdates the self-asserted when to 'produce' records dated before the compromise. OPEN: authoritative time = Rekor anchor integratedTime, not when.
- **vulnerable at:** pk [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea)
- **PoC:** [`attacks/backdated-production.sh`](attacks/backdated-production.sh)

### `canon-bigint` — RED · ✅ closed
- **class:** `canonicalization`
- **theory:** nekton claim rounded an integer > 2^53 through float64 BEFORE signing, so the signer signed a different number. Fixed: rejected at the canon boundary (RFC 8785 App D).
- **vulnerable at:** pk [`24dfc6b`](https://github.com/gitmick/plankton/commit/24dfc6b)
- **fixed at (reproduction now fails):** pk [`1e667f3`](https://github.com/gitmick/plankton/commit/1e667f3)
- **PoC:** [`attacks/canon-bigint.sh`](attacks/canon-bigint.sh)

### `co-signer-drop` — ORANGE · ✅ closed
- **class:** `federation-not-order-independent`
- **theory:** Two valid co-signers of one statement collided on one id; mirror order decided which signature survived. Fixed: union signatures per claim id.
- **vulnerable at:** pk [`0aa44b8`](https://github.com/gitmick/plankton/commit/0aa44b8)
- **fixed at (reproduction now fails):** pk [`b625b1f`](https://github.com/gitmick/plankton/commit/b625b1f)
- **PoC:** [`attacks/co-signer-drop.sh`](attacks/co-signer-drop.sh)

### `scope-path-traversal` — RED · ✅ closed
- **class:** `path-from-unvalidated-input`
- **theory:** A claim's `scope` is a free-form string in a signed payload, and the store derived a
  filename from it without validation. `scope: "sha256:../../../tmp/x"` made nekton create and
  append to a file anywhere the process could write; ingesting the same claim twice then sent it
  through `rewriteSubnekton`, which atomically replaced that file with only the attacker's record,
  destroying whatever else it held. Reachable from a hostile peer: `kton mirror nekton` feeds peer
  envelopes straight to `Add`, and ingest does not verify signatures (§8), so any key suffices.
- **why it survived:** the same class was found and fixed in the blobstore (#79) — validate before
  deriving a path — and left standing in the store layout added by #41. One kernel learned the
  lesson and the other did not.
- **fixed at:** #87 — a scope must be a canonical content hash before it can name a file, and the
  result is proven to stay under the store root. One guarded derivation now serves both the record
  file and its verification material, so the two cannot drift apart again.
- **PoC:** [`attacks/scope-path-traversal.sh`](attacks/scope-path-traversal.sh) — gated. Verified to
  report VULNERABLE against the pre-fix binary and PREVENTED after.

### `concurrency-races` — ORANGE · ✅ closed (and once recorded closed in error)
- **class:** `concurrency-nonatomic`
- **theory:** Concurrent same-file writers corrupted objects and dropped a co-signature (non-atomic os.WriteFile).
- **status:** Closed in two halves, years apart in effort. `af3cefa` made each write atomic
  (temp+rename), ending the torn-object half — and this entry then claimed a "locked union-write"
  that did not exist. Atomic rename makes each write indivisible; it does nothing for a
  read-modify-write spanning two of them, so two processes co-signing one record each merged into a
  stale in-memory view and the second rename discarded the first's signature. The union now takes a
  per-object lock and RE-READS from disk under it (#77). The lock is per object file, not
  store-wide: writers contend only on the same record, and a bulk ingest of distinct records has
  nothing to serialize.
- **vulnerable at:** pk [`a687723`](https://github.com/gitmick/plankton/commit/a687723)
- **atomic write at:** pk [`af3cefa`](https://github.com/gitmick/plankton/commit/af3cefa)
- **PoC:** [`attacks/concurrency-races.sh`](attacks/concurrency-races.sh) — gated. It was a stub
  printing a sentence and no verdict, which is exactly why the gate could not see this for as long
  as it did; made executable first, then fixed.

### `corrupt-poisons-read` — ORANGE · ✅ closed
- **class:** `read-face-brittle`
- **theory:** One malformed record aborted the ENTIRE registry read (both kernels). Fixed: skip + warn the offending file, the read survives.
- **vulnerable at:** pk [`ed7a008`](https://github.com/gitmick/plankton/commit/ed7a008)
- **fixed at (reproduction now fails):** pk [`056b87a`](https://github.com/gitmick/plankton/commit/056b87a)
- **PoC:** [`attacks/corrupt-poisons-read.sh`](attacks/corrupt-poisons-read.sh)

### `envtally-CF2` — RED · ✅ closed
- **class:** `gate-trusts-recorded-tally`
- **theory:** env-qualified branch checked only that the fulfilment foton prov:used the spectrum, never that its tally passed; a 2/3 FAILED qualification was accepted as 3/3.
- **vulnerable at:** kx [`3619db4`](https://github.com/gitmick/kton-examples/commit/3619db4)
- **fixed at (reproduction now fails):** kx [`0f3dafa`](https://github.com/gitmick/kton-examples/commit/0f3dafa)
- **PoC:** [`attacks/envtally-CF2.sh`](attacks/envtally-CF2.sh)

### `export-attribution` — RED · ✅ closed
- **class:** `export-trusts-claimed-keyid`
- **theory:** export --rdf set prov:wasAttributedTo from the unverified keyid; a relabelled foton attributed production to a victim. Fixed: unverified -> nk:claimedSigner.
- **vulnerable at:** pk [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938)
- **fixed at (reproduction now fails):** pk [`e92beca`](https://github.com/gitmick/plankton/commit/e92beca)
- **PoC:** [`attacks/export-attribution.sh`](attacks/export-attribution.sh)

### `federation-withholding` — YELLOW · ⚪ boundary
- **class:** `closed-world-boundary`
- **theory:** A verifier sees only the sources it names; a withheld source (or revocation) removes nothing it should. Documented closed-world limit: a verdict must NAME the sources it consulted; withholding has leverage only at the closed-world gate.
- **vulnerable at:** pk [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea)
- **PoC:** [`attacks/federation-withholding.sh`](attacks/federation-withholding.sh)

### `fourEyes-graphpoll` — RED · ✅ closed
- **class:** `gate-trusts-mutable-graph-edge`
- **theory:** Four-eyes resolved the author via ?fit prov:wasAttributedTo ?rauthor, existential over the merged graph; one injected attribution edge let a self-review pass.
- **vulnerable at:** kx [`ac188cb`](https://github.com/gitmick/kton-examples/commit/ac188cb)
- **fixed at (reproduction now fails):** kx [`4931c42`](https://github.com/gitmick/kton-examples/commit/4931c42)
- **PoC:** [`attacks/fourEyes-graphpoll.sh`](attacks/fourEyes-graphpoll.sh)

### `fourEyes-max` — RED · ✅ closed
- **class:** `gate-trusts-mutable-graph-edge`
- **theory:** Independence as a SPARQL existential pair-join counted one key bound to two principals as two reviewers. Fixed by counting in the driver, not the graph.
- **vulnerable at:** kx [`b2616d7`](https://github.com/gitmick/kton-examples/commit/b2616d7)
- **fixed at (reproduction now fails):** kx [`56ae3cd`](https://github.com/gitmick/kton-examples/commit/56ae3cd)
- **PoC:** [`attacks/fourEyes-max.sh`](attacks/fourEyes-max.sh)

### `nanopub-signed-eq-published` — RED · ✅ closed
- **class:** `render-face-doesnt-escape`
- **theory:** The RSA-signed quad set diverged from the published TriG; a tampered nanopub kept signature + Trusty URI byte-identical. Fixed: publish exactly the signed quads.
- **vulnerable at:** pk [`9ea6938`](https://github.com/gitmick/plankton/commit/9ea6938)
- **fixed at (reproduction now fails):** pk [`1a8c798`](https://github.com/gitmick/plankton/commit/1a8c798)
- **PoC:** [`attacks/nanopub-signed-eq-published.sh`](attacks/nanopub-signed-eq-published.sh)

### `no-revocation` — RED · 🔴 OPEN
- **class:** `no-key-lifecycle`
- **theory:** kton has no revocation/validity notion: a revoked or compromised key's signatures verify as authoritative forever. OPEN: revocation as an additive signed claim + a time-aware trust filter.
- **vulnerable at:** pk [`1447cea`](https://github.com/gitmick/plankton/commit/1447cea)
- **PoC:** [`attacks/no-revocation.sh`](attacks/no-revocation.sh)

### `normalizer-forge` — RED · ✅ closed
- **class:** `backstop-looks-up-not-reexecute`
- **theory:** Act-8a step 1 used reproduces --via, a LOOKUP over sponsor-recorded normalize fotons; two fotons both --out one canon laundered different outputs to L1. Fixed by re-executing a trusted normalizer.
- **vulnerable at:** kx [`2024ca5`](https://github.com/gitmick/kton-examples/commit/2024ca5)
- **fixed at (reproduction now fails):** kx [`dee089c`](https://github.com/gitmick/kton-examples/commit/dee089c)
- **PoC:** [`attacks/normalizer-forge.sh`](attacks/normalizer-forge.sh)

### `rdf-injection` — RED · ✅ closed
- **class:** `render-face-doesnt-escape`
- **theory:** export --nanopub emitted a signed claim's object string as an unescaped Turtle term, injecting an extra triple into the SIGNED assertion graph. Fixed by percent-escaping object IRIs.
- **vulnerable at:** pk [`2e896c8`](https://github.com/gitmick/plankton/commit/2e896c8)
- **fixed at (reproduction now fails):** pk [`804f052`](https://github.com/gitmick/plankton/commit/804f052)
- **PoC:** [`attacks/rdf-injection.sh`](attacks/rdf-injection.sh)

### `scope-truncation` — ORANGE · ✅ closed
- **class:** `freshness-monotone-boundary`
- **theory:** A withheld MIDDLE claim silently truncated a sealed scope. Fixed: nekton head flags a possibly-truncated scope (a withheld TAIL claim stays in-band undetectable — a monotone-design boundary, caveated).
- **vulnerable at:** pk [`a687723`](https://github.com/gitmick/plankton/commit/a687723)
- **fixed at (reproduction now fails):** pk [`8bbdf54`](https://github.com/gitmick/plankton/commit/8bbdf54)
- **PoC:** [`attacks/scope-truncation.sh`](attacks/scope-truncation.sh)

### `screenshot-viewer-labels` — RED · ✅ closed
- **class:** `viewer-trusts-declared-id`
- **theory:** The viewer rendered an unauthenticated human label on a green-verified node, so a reader screenshots an approval the corpus does not support. Fixed: a name is ATTESTED only via a trusted-authority sec:controller binding; else the viewer marks it 'unverified id' (the green ring verifies the KEY, not the name).
- **vulnerable at:** kx [`46ed3fa`](https://github.com/gitmick/kton-examples/commit/46ed3fa)
- **fixed at (reproduction now fails):** kx [`b2616d7`](https://github.com/gitmick/kton-examples/commit/b2616d7)
- **PoC:** [`attacks/screenshot-viewer-labels.sh`](attacks/screenshot-viewer-labels.sh)

### `silent-source-drop` — ORANGE · ✅ closed
- **class:** `read-face-silent-partial`
- **theory:** A missing/unreachable --source was silently dropped (exit 0), so a federated read could lose a whole source with no signal. Fixed: a missing --source is an error.
- **vulnerable at:** pk [`ed7a008`](https://github.com/gitmick/plankton/commit/ed7a008)
- **fixed at (reproduction now fails):** pk [`056b87a`](https://github.com/gitmick/plankton/commit/056b87a)
- **PoC:** [`attacks/silent-source-drop.sh`](attacks/silent-source-drop.sh)

### `spectrum-existence` — ORANGE · ✅ closed
- **class:** `spectrum-no-existence-check`
- **theory:** spectrum check reported FULFILLED for invented member hashes backing no foton. Fixed: a member/candidate must resolve to a produced foton.
- **vulnerable at:** pk [`7df1e70`](https://github.com/gitmick/plankton/commit/7df1e70)
- **fixed at (reproduction now fails):** pk [`05a94d8`](https://github.com/gitmick/plankton/commit/05a94d8)
- **PoC:** [`attacks/spectrum-existence.sh`](attacks/spectrum-existence.sh)

### `spectrum-launder` — RED · ✅ closed
- **class:** `backstop-looks-up-not-reexecute`
- **theory:** Act-8a step 2 re-ran spectrum check but never re-executed the normalizer, so an unqualified environment + one lying normalize foton passed as fully qualified. Fixed: the regulator re-executes the trusted normalizer per normalized member, and re-qualifies the normalizer program itself.
- **vulnerable at:** kx [`24bd5af`](https://github.com/gitmick/kton-examples/commit/24bd5af)
- **fixed at (reproduction now fails):** kx [`46ed3fa`](https://github.com/gitmick/kton-examples/commit/46ed3fa)
- **PoC:** [`attacks/spectrum-launder.sh`](attacks/spectrum-launder.sh)

### `suppress-replay` — RED · ✅ closed
- **class:** `read-face-trusts-declared-id`
- **theory:** Replay trusted the on-disk fotonId instead of re-deriving it; a planted collision-id decoy silently erased a present record from producer/uses/lineage and nekton about/by.
- **vulnerable at:** pk [`7df1e70`](https://github.com/gitmick/plankton/commit/7df1e70)
- **fixed at (reproduction now fails):** pk [`d0f7cf9`](https://github.com/gitmick/plankton/commit/d0f7cf9)
- **PoC:** [`attacks/suppress-replay.sh`](attacks/suppress-replay.sh)

### `viewer-selfsigned` — RED · ✅ closed
- **class:** `viewer-trusts-declared-id`
- **theory:** An empty trust box rendered a self-signed sec:controller binding as an attested senior identity. Fixed: an empty trust box trusts NO binding.
- **vulnerable at:** kx [`b8a642a`](https://github.com/gitmick/kton-examples/commit/b8a642a)
- **fixed at (reproduction now fails):** kx [`f5570c0`](https://github.com/gitmick/kton-examples/commit/f5570c0)
- **PoC:** [`attacks/viewer-selfsigned.sh`](attacks/viewer-selfsigned.sh)

### `viewer-xss` — RED · ✅ closed
- **class:** `render-face-doesnt-escape`
- **theory:** A claim's by field carrying markup rendered as a live <img onerror> in a green-verified viewer node. Fixed: HTML-escape all record-derived fields.
- **vulnerable at:** kx [`826ea7d`](https://github.com/gitmick/kton-examples/commit/826ea7d)
- **fixed at (reproduction now fails):** kx [`b8a642a`](https://github.com/gitmick/kton-examples/commit/b8a642a)
- **PoC:** [`attacks/viewer-xss.sh`](attacks/viewer-xss.sh)

### `wasm-viewer-trust` — RED · ✅ closed
- **class:** `viewer-trusts-declared-id`
- **theory:** graph.wasm trusted the declared fotonId/keyid (never recomputed) and short()=48-bit collided distinct artifacts. Fixed: re-derive id + 128-bit node identity.
- **vulnerable at:** pk [`804f052`](https://github.com/gitmick/plankton/commit/804f052)
- **fixed at (reproduction now fails):** pk [`6ff639e`](https://github.com/gitmick/plankton/commit/6ff639e)
- **PoC:** [`attacks/wasm-viewer-trust.sh`](attacks/wasm-viewer-trust.sh)

### `when-unvalidated` — ORANGE · ✅ closed
- **class:** `unvalidated-timestamp`
- **theory:** A claim's non-RFC3339 when (e.g. garbage text) was signed, ingested, and displayed as authoritative. Fixed: rejected at the ingest gate (registry.Add -> Validate, RFC 3339). A well-formed far-future/backdated when stays accepted - a monotone-design boundary; semantic freshness = anchor time (see backdated-production).
- **vulnerable at:** pk [`e5c01e2`](https://github.com/gitmick/plankton/commit/e5c01e2)
- **fixed at (reproduction now fails):** pk [`e8da93c`](https://github.com/gitmick/plankton/commit/e8da93c)
- **PoC:** [`attacks/when-unvalidated.sh`](attacks/when-unvalidated.sh)

---
*Generated from the signed graph. `gitmick/kton-examples` permalinks are public; `gitmick/plankton` resolves for repo members (plankton is not yet public).*
