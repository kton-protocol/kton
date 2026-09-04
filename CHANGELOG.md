# Changelog

## 0.2.0 — unreleased

### ⚠️ Read this before upgrading a nekton registry

**A nekton store written by 0.2 reads as EMPTY on 0.1, and 0.1 exits 0 while saying so.**

```
$ NEKTON_DIR=<a 0.2 store> nekton-0.1 about sha256:...
(none)
$ echo $?
0
```

The claims are there, signed, intact. A 0.1 binary looks for `objects/**/*.json`, finds none, and
reports an empty registry successfully — a verification tool answering *"nothing is recorded"*
where the truthful answer is *"I cannot read this store"*. There is no marker in a 0.1-era store
that could have prevented this, which is why the layout change ships as a minor version rather
than a patch, and why this note is the first thing in the file.

**What to do:** upgrade every binary that touches a shared registry at the same time. Do not point
a 0.1 binary at a 0.2 store to "check something quickly". If a registry is served or mirrored,
upgrade the server before the peers.

**Going forward this cannot recur.** A 0.2 store records its layout in `objects/.format`, and any
build reading a format it does not know refuses loudly instead of reporting an empty registry.

### Changed

- **A subnekton is one file** (#41). A nekton store is now one JSONL file per scope plus one for
  the unscoped nekton:

  ```
  objects/scope/<scope_id>.nekton.jsonl    a subnekton: its seed and every claim chained under it
  objects/unscoped.nekton.jsonl            the unscoped nekton
  objects/.format                          the layout marker
  ```

  A scope is a bounded, federatable sub-registry, and this gives it one artifact — a thing that can
  be chmod'd, sparse-checked-out, copied or handed over whole, none of which a flat pile of
  per-claim hashes can be. The file is a bag, not a sequence: order stays the chain's alone
  (`prev`), so the file never becomes a second, unsigned representation of order that could drift
  from the signed one. Reads still resolve pre-0.2 per-claim objects, and a write migrates a record
  the first time it touches it, so an existing store keeps working and converts as it is used.

- **`sync(since)` stops losing records** (#97, AUD-02). §12 always said the answer is "records with
  a local sequence above `since`, **in append order**". Both kernels instead derived that sequence
  from the record's rank in the hash-sorted store, recomputed on every load — so the one guarantee a
  cursor exists to give (*ask again with this number and you lose nothing*) did not hold. In plain
  use, only a record whose hash happened to sort last was ever delivered to an already-synced peer:
  measured at **7 of 8** new records silently withheld. It is also grindable — a scope id is the
  hash of a seed an attacker writes, and a scope that sorts early pushes an existing scope's records
  back under the peer's cursor for good (1–20 attempts, measured).

  A position is now issued **once**, at first sight, and never recomputed. It lives in a `.seq` file
  next to `peers.json` — deliberately outside `objects/`, so the record tree a git federation ships
  stays byte-identical across peers and conflict-free to merge. Gated as `cursor-shift`.

  **On upgrade:** an existing store is numbered on first open, in the same order it was already
  being numbered in, so peers do not re-sync. Positions are not dense — a record that is dropped or
  refused may still consume one — and gaps carry no meaning.

- Claim ids, envelopes, signatures and the wire format are unchanged. `specVersion` stays `0.1`:
  this is a storage layout revision, not a protocol change.

### Changed

- **`pin` and `blob` are plankton commands** (#102). `plankton pin <file>` and
  `plankton blob <sha256:…>`. Pinning needs no address — a hash says *what*, and the bytes are
  already on this machine — so it was never a cockpit capability. Fetching bytes that are **not**
  here is a different thing and stays in the cockpit (`kton fetch`).

  The store's location moves with them: `blobstore.Subdir` and `blobstore.OpenFor(registryDir)`
  replace a `filepath.Join` every caller wrote by hand against a constant that lived in the
  cockpit's `federation` package — plankton's own storage layout declared in a package that
  *depends on* plankton.

  The path is unchanged (`<registry>/blobs`), so an existing store stays readable and both
  spellings reach the same bytes; a test pins that layout so a later refactor cannot quietly
  relocate everyone's pinned data. `kton pin` and `kton blob` still work and print a deprecation
  note; they go when the cockpit leaves the repository.

### Fixed

- **A claim spec could name a subject that silently disappeared** (#106). The authoring spec spells a
  subject `hash: "sha256:…"`; the signed statement spells the same thing `digest: {sha256: …}` (the
  in-toto form, SPEC §7.3). Anyone who read a signed statement and reasoned backwards wrote `digest`
  in the spec — `encoding/json` dropped the field it did not know, and the subject rendered as `{}`.

  ```
  in                          out
  {hash:"sha256:…"}           {digest:{sha256:…}}   ok
  {name, hash:"sha256:…"}     {digest, name}        ok
  {digest:{sha256:…}}         {}                    everything gone, in silence
  {name, digest:{…}}          {name}                the hash gone, in silence
  ```

  The claim was then **signed, ingested, verified and attachable** — and about nothing. `about <hash>`
  could never reach it, because it was about no hash. `show` printed `subject:` followed by an empty
  line. Not one word of warning.

  Three changes, because the hole had three mouths:

  1. `Validate` now refuses a subject entry whose `Key()` is empty — neither a `digest` nor a `uri`.
     Counting the subjects was never enough; `subject: []` was refused while `subject: [{}]` passed.
     It sits at the gate **every** claim crosses, so a record arriving by mirror or by a git merge is
     caught too, not only one authored locally. A `name` alone is a label, not an identity.
  2. `ParseSpec` refuses an **unknown field** instead of dropping it, and says what to write instead
     when it sees `digest`. A misspelling in a document about to be signed must never be an omission;
     this also catches `predicat`, `subjects`, and every other typo at the one place a human writes
     the file.
  3. `verify` now reports the **structure** as well as the signature, in both kernels, and exits 3
     when the signature is genuine but ingest would refuse the record. A valid signature says who
     signed the bytes, not that the substrate will store them — so `verify` used to issue a clean
     bill of health for a claim `add` rejects, and anyone who verified a file without adding it
     believed it was good. Exit 0 now means genuine **and** storable; 1 and 2 keep their meanings.

  Found by the examples workstream while writing claims by hand. One of the project's own test
  fixtures had fallen into the same trap: `claim_test.go` built a Statement with `subject: [{"hash":
  …}]`, which is the spec spelling in the wire position, and had been asserting over a claim about
  nothing — green the whole time.

### Removed

- **The HTTP federation client** (#101) — `kton mirror <url>`, the `kton/federation` package, and
  the two raw `http.Get` call sites behind `--with-material`. `kton serve` went in #83; this is the
  other half. A protocol repository is about bytes, not about which other protocol carries them
  somewhere: §12 fixes the queries and the wire form and leaves the **transport** unspecified, and
  the HTTP binding in Annex C is informative.

  It had **no caller**. `kton mirror` appears 25 times across the examples, the cockpit and
  kton-web — not once with an `http(s)://` peer. The only URL occurrences anywhere were two lines
  of documentation.

  Three of the four unbounded HTTP clients in the repository disappear with it, rather than being
  hardened: `federation.Sync` and `federation.GetBlob` (no timeout; `GetBlob` read the **whole**
  body into memory before comparing the hash), `nektonHTTPMirror`, and the material pull that made
  one untimed request **per claim id**. `mirror --pin` and `mirror --with-material` go too: both
  only ever did anything for a URL peer and were silent no-ops on a local directory.

  **What replaces it:** nothing, because nothing used it. `plankton records --json --since N` and
  `nekton records --json --since N` answer `sync(since)` on stdout — the binding the cockpit
  already reads. Mirroring a local registry directory is unchanged and stays in the kernels
  (`plankton mirror` / `nekton mirror`); a URL is now refused with a message saying where the
  capability went.

  The deleted package held the only tests over the §12 conformance vectors, and they tested the
  **consuming** side. They are replaced by a producer-side test that asserts
  `plankton records --json` re-emits `testdata/federation/sync-plankton.json` as the same document —
  the direction that matters now, and the first thing to actually compare the two.

### Added

- **`plankton records` / `nekton records`** (#85) — every record with its signed envelope, the
  Clause 12 `sync(since)` answer on stdout. `plankton show --json` now carries the envelope too: a
  consumer that has to *verify* needs the bytes the signature stands over, and a projection is not
  those bytes.
- **`plankton attach` / `material`, `nekton attach` / `material`** (#62, #64) — bind external
  verification material to a record by its content address (§8.1) and read back what is attached.
  Stored, never evaluated.
- **`kton anchor --store`** (#62) — record the verified Rekor entry on the record, which is what §13
  asks for; without it the proof only ever reached stdout.
- **`kton mirror --with-material`** (#62) — make this copy of the evidence complete, asking the peer
  about every claim held rather than about the last sync batch.
- **`--print-id`** on `nekton claim`, `annotate` and `seed` (#56) — the bare id alone on stdout, the
  contract `plankton author` already had. `plankton add` too (#74).
- **`--json`** on `plankton producer`/`uses`/`lineage`/`reproductions`/`reuse` and `nekton head`
  (#57, #74, #89). A record's id is a named field there, so nothing has to assume it is the first
  hash on a line — and `reproduces --json` reports its **level** as a field, which a signed
  `reproduces` claim records and which the exit code cannot distinguish.
- **`kton fetch --allow-local`** (#81) — see Security.

### Changed

- **`pin` and `blob` are plankton commands** (#102). `plankton pin <file>` and
  `plankton blob <sha256:…>`. Pinning needs no address — a hash says *what*, and the bytes are
  already on this machine — so it was never a cockpit capability. Fetching bytes that are **not**
  here is a different thing and stays in the cockpit (`kton fetch`).

  The store's location moves with them: `blobstore.Subdir` and `blobstore.OpenFor(registryDir)`
  replace a `filepath.Join` every caller wrote by hand against a constant that lived in the
  cockpit's `federation` package — plankton's own storage layout declared in a package that
  *depends on* plankton.

  The path is unchanged (`<registry>/blobs`), so an existing store stays readable and both
  spellings reach the same bytes; a test pins that layout so a later refactor cannot quietly
  relocate everyone's pinned data. `kton pin` and `kton blob` still work and print a deprecation
  note; they go when the cockpit leaves the repository.

### Fixed

- **`nekton seed --when` / `nekton annotate --when`** (#42). `when` is covered by the claim id, and a
  scope id *is* its seed's claim id — so a wall-clock timestamp made the identity a function of when
  you ran the command. A 2243-claim corpus rebuilt three times produced three different root ids,
  and every child scope and claim moved with it. Pin the timestamp and a rebuild lands on the same
  ids. A non-RFC-3339 value is refused before signing, not at ingest: a timestamp caught after
  signing has already been signed.

- **`keygen --seed <64-hex>` and `pubkey <key.key|hex>`**, both kernels (#44). The sibling of #42 for
  the other half of a record's identity: the public key sits inside every signed payload, so a random
  key per run moved every record id no matter how fixed `when` was. A hand-written seed was already
  accepted as a `.key`; what was missing was the way back to the `.pub` hex that `verify`,
  `--trust-keys` and the viewer key directories read. With both, two runs of the same corpus produce
  a byte-identical store. A seeded key is only as strong as its seed — for fixtures, not for an
  identity anyone must trust.

- `plankton add` no longer needs one process per record for bulk ingest (#37).
- `nekton about` / `nekton by` emit structured JSON with `--json`, so a consumer can read the claim
  axis without parsing prose (#39).
- Foton authoring lifted out of the CLI into `kton.dev/plankton/foton` (#35).
- A claim about a URI subject renders as an edge, not a floating node (#33).

### Security

- **`kton fetch` no longer dereferences a locator nobody verified** (#81). A located-at claim is a
  suggestion from whoever signed it, and ingest stores signed claims *without* verifying them
  (§8: the wire carries a keyid, not a key) — so anyone able to put a claim in front of a registry
  chose the URI this process opened. Dereferencing is a request made from the host, and for
  `file://` a read of its disk; the hash check afterwards proves what the bytes are, cannot undo the
  request, and for a file whose hash is known does not even reject the result.

  `--trust-keys <dir>` is now required, the signer is derived from the key that actually verifies
  (never the declared keyid), `file://` and addresses on this host or network need `--allow-local`
  on top, redirects are re-checked against the same rule, and a body is bounded.

- **`blobstore` refuses a path built from anything that is not a content hash** (#79), and `/blob`
  answers 400 rather than 404 for a malformed one. Fixing it surfaced a second bug: `Get` compared
  the content hash against the caller's *spelling*, so an uppercase or bare digest found its file
  and then reported it corrupt.

### Security suite

- **The plankton registry takes a lock around its signature union** (#77), and re-reads from disk
  under it. `concurrency-races` was VULNERABLE on every run: the union merged against this process's
  in-memory copy, so two processes co-signing one record each merged into a stale view and the
  second atomic rename discarded the first's signature. Atomic rename makes each write indivisible;
  it does nothing for a read-modify-write spanning two of them. The lock is **per object file**, not
  store-wide — writers contend only on the same record, and a bulk ingest of distinct records has
  nothing to serialize. `peers.json` gets its own, and merges cursors by maximum rather than
  overwriting, so two concurrent mirrors cannot lose one another's position. Posture returns to 24
  closed / 2 open, this time with an executable PoC behind the claim.

- `security/REPORT.md` recorded `concurrency-races` as closed with an "atomic temp+rename + locked
  union-write". There is no lock in the plankton registry — nekton serialises its union with
  `.objects.lock`, plankton does not — so two processes still lose a co-signature. Reopened, with
  the half that was genuinely fixed (the atomic write) stated as such. Posture is now 23 closed /
  3 open, not 24 / 2.
- The `concurrency-races` PoC was a stub that printed a sentence and no verdict, so the gate could
  not see the gap. It is executable now and loses a signature in every run.
- `security/check.sh` gained an `OPEN` list, so a known-open finding runs and reports without
  failing the build; it prints its own coverage ratio (10 of 28 recorded attacks) and names a
  skipped attack instead of dropping it silently from the gate.
- `security/README.md` claimed every PoC prints a verdict and that the gate runs them all; 18 of 28
  print none and it ran 9. `REPORT.md` claimed it could be regenerated by
  `provenance/render_report.py` and verified against `keys/redteam.pub`; neither the renderer, the
  signed claims nor `keys/` are in this repository. Both corrected.
- Attack PoCs read the nekton store through `security/attacks/_records.sh` instead of globbing a
  layout. Three of them hardcoded `objects/sha256/*.json` and reported a false regression under the
  new layout while the property they test still held.

### Changed

- **`pin` and `blob` are plankton commands** (#102). `plankton pin <file>` and
  `plankton blob <sha256:…>`. Pinning needs no address — a hash says *what*, and the bytes are
  already on this machine — so it was never a cockpit capability. Fetching bytes that are **not**
  here is a different thing and stays in the cockpit (`kton fetch`).

  The store's location moves with them: `blobstore.Subdir` and `blobstore.OpenFor(registryDir)`
  replace a `filepath.Join` every caller wrote by hand against a constant that lived in the
  cockpit's `federation` package — plankton's own storage layout declared in a package that
  *depends on* plankton.

  The path is unchanged (`<registry>/blobs`), so an existing store stays readable and both
  spellings reach the same bytes; a test pins that layout so a later refactor cannot quietly
  relocate everyone's pinned data. `kton pin` and `kton blob` still work and print a deprecation
  note; they go when the cockpit leaves the repository.

### Fixed

- **A claim spec could name a subject that silently disappeared** (#106). The authoring spec spells a
  subject `hash: "sha256:…"`; the signed statement spells the same thing `digest: {sha256: …}` (the
  in-toto form, SPEC §7.3). Anyone who read a signed statement and reasoned backwards wrote `digest`
  in the spec — `encoding/json` dropped the field it did not know, and the subject rendered as `{}`.

  ```
  in                          out
  {hash:"sha256:…"}           {digest:{sha256:…}}   ok
  {name, hash:"sha256:…"}     {digest, name}        ok
  {digest:{sha256:…}}         {}                    everything gone, in silence
  {name, digest:{…}}          {name}                the hash gone, in silence
  ```

  The claim was then **signed, ingested, verified and attachable** — and about nothing. `about <hash>`
  could never reach it, because it was about no hash. `show` printed `subject:` followed by an empty
  line. Not one word of warning.

  Three changes, because the hole had three mouths:

  1. `Validate` now refuses a subject entry whose `Key()` is empty — neither a `digest` nor a `uri`.
     Counting the subjects was never enough; `subject: []` was refused while `subject: [{}]` passed.
     It sits at the gate **every** claim crosses, so a record arriving by mirror or by a git merge is
     caught too, not only one authored locally. A `name` alone is a label, not an identity.
  2. `ParseSpec` refuses an **unknown field** instead of dropping it, and says what to write instead
     when it sees `digest`. A misspelling in a document about to be signed must never be an omission;
     this also catches `predicat`, `subjects`, and every other typo at the one place a human writes
     the file.
  3. `verify` now reports the **structure** as well as the signature, in both kernels, and exits 3
     when the signature is genuine but ingest would refuse the record. A valid signature says who
     signed the bytes, not that the substrate will store them — so `verify` used to issue a clean
     bill of health for a claim `add` rejects, and anyone who verified a file without adding it
     believed it was good. Exit 0 now means genuine **and** storable; 1 and 2 keep their meanings.

  Found by the examples workstream while writing claims by hand. One of the project's own test
  fixtures had fallen into the same trap: `claim_test.go` built a Statement with `subject: [{"hash":
  …}]`, which is the spec spelling in the wire position, and had been asserting over a claim about
  nothing — green the whole time.

### Removed

- **`kton serve`, and the whole HTTP server** (#83) — the largest breaking change in this release.
  `federation.NewServer`, the nekton handler, the `serve` verb, and with them the `:8787`/`:8788`
  defaults. **A consumer that read a registry over `/sync` must move to `plankton records --json
  --since N` / `nekton records --json --since N`**, which return exactly the same document on stdout.

  SPEC Clause 12 was restated first: the queries and the wire form are normative, the transport is
  not, and the HTTP binding moved to informative Annex C. A specification of a protocol is not a
  place to distribute a network service — a listening socket brings authentication, transport
  security, rate limiting and request bounds with it, and those belong to a deployment. Writing a
  server over the Clause 12 table is a small amount of code in any language, and
  `reference/testdata/federation/` fixes the bytes it must produce.

  The federation **client** is unaffected: `kton mirror` over a URL or a directory still works.


- **`kton/reference/web/graph/`** (#72) - ~2500 lines of browser-facing code, and with it the
  `graph.wasm` release artifact, its `wasm_exec.js`, their checksums and the `graph.wasm.buildinfo`
  recipe. Nothing in Go imported it; it was a leaf `package main` whose own harness described it as
  validating "the exact logic that the wasm build serves to the browser". kton-web already built it,
  copying `graph.go` and `sign.go` out of a pinned kernel checkout, and already superseded
  `main_wasm.go` with its own export groups. It belongs there.

  The reproducibility check moves rather than dies - two builds from different directories with
  `-trimpath`, required to be byte-identical - because reproducibility of a browser artifact is
  kton-web's concern. What stayed here is the kernels' own obligation to compile for
  `GOOS=js GOARCH=wasm` (`CONTRIBUTING.md:13`), which CI now proves by compiling rather than by
  grepping imports.

  Consumers of the `graph.wasm` release asset must take it from kton-web from 0.2 on.

- The 3.7 MB unstripped native harness binary that `web/graph` had committed into the tree.
