# Changelog

## 0.2.0 — unreleased

### ⚠️ Known limitation in 0.2: a claim can lose a signature when the same claim arrives twice

**Not fixed in this release.**

A claim id is `sha256(canon(Statement))`, so two DIFFERENT serializations of one statement — a
compact one and a pretty-printed one, say — share a claim id while carrying signatures over
**different literal payload bytes**. A DSSE signature stands over `PAE(payloadType, payload)`, so
these are two genuine signatures over two genuine byte strings, neither of them wrong.

nekton's signature union correctly refuses to attach a signature to bytes its owner did not sign.
Persistence then misreads that refusal as *nothing new to store*:

```
Add A (compact, key A):  isNew=true   err=<nil>
Add B (pretty,  key B):  isNew=false  err=<nil>     <- reported as a duplicate
same claim id:           true
after reopen:            1 signature, key A only
BySigner(A)=1   BySigner(B)=0
```

Reverse the arrival order and the result reverses with it: `BySigner(A)=0  BySigner(B)=1`.

**What this costs you.** The second signer's evidence is gone, and nothing says so — `Add` returned
success. Because the outcome depends on which serialization arrived first, **mirroring is
order-dependent**: two peers that ingest the same two envelopes in different orders end up retaining
different signatures, and a consumer's ability to verify against the key *it* trusts becomes an
accident of replication order. This is loss of signing evidence, not signature forgery: nothing here
lets anyone produce a signature they could not otherwise produce.

**What you can do now.** Within one authoring toolchain the payload is canonical every time, so the
case does not arise: it needs two producers, or a hand-assembled envelope, signing the same statement
in different spellings. If you federate signed claims from parties you do not control, and you rely
on a specific signer's endorsement being present, verify that signer against the envelope you
received rather than against the merged store.

**Why it is not fixed here.** The fix is a storage decision — preserve distinct signed envelope
variants under one canonical claim id, and union signatures only where the signed bytes actually
match — and it changes how claims are persisted. Rushing it risks exactly what it is meant to
prevent: canonicalizing payloads on the way in would leave old signatures standing over bytes nobody
signed. It is scheduled with the shared-validator work rather than taken in a hurry before a tag.

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

### Fixed — a gated proof that proved nothing, and a coverage claim that was not true

- **`fourEyes-graphpoll` could not conclude anything, twice over.** Its closing
  `grep -E 'two distinct PRINCIPALS'` could never match — `release.py` prints "two distinct
  **authority-vouched** PRINCIPALS" — and `|| true` swallowed that, so it exited 0 having printed
  nothing. Worse, it emitted **no `VERDICT:` line at all**, so `check.sh` could not have read a result
  even with the grep repaired.

  And the scenario left **all seven** conditions unticked, so "four-eyes stayed unticked" was true
  with and without the attack — precisely the defect this suite found in `envtally-CF2` and downgraded
  to INCONCLUSIVE for.

  It now runs **four** scenarios over the shipped gate: two genuine vouched reviewers (must tick — and
  does, which is what makes the rest evidence), one genuine reviewer plus the author reviewing its own
  fit (must not), that plus the injected attribution edge (must not — **PREVENTED**), and the honest
  case *with* the decoy, reported rather than required. That last one answered a question worth
  asking: it stays ticked, so the injected claim cannot block a legitimate release either. `release.py`
  ignores it because `Q_AUTHOR` counts only verified agents.

- **An executable PoC in neither `GATED` nor `OPEN` was invisible**, which is how the above went
  unnoticed: nothing ran it, so `self-check.sh` never saw it and the can-it-fail guard did not cover
  it. `check.sh` now **fails** if a PoC that emits a verdict is in neither list. Sixteen scripts are
  unlisted; thirteen are one-line prose notes and stay that way.

- **`security/README.md` claimed coverage that does not exist:** *"The example-12 gate attacks
  (four-eyes, spectrum-launder, normalizer-forge) run against the full capstone in the kton-examples
  CI."* They do not — that workflow builds binaries, runs the examples and checks permalinks, and has
  no such step. The same false framing was in `check.sh`'s own coverage line. Both corrected, with
  each of the three named and its actual status given.

- **`normalizer-forge` took the binary path as `$1`** where every other PoC takes a kton-examples
  checkout, which is what made the first attempt to run it look like a failure. It now uses `plankton`
  from PATH like the rest, and reads the store through `_records.sh` instead of globbing
  `objects/sha256/*.json` — the very trap that helper exists to close. It stays verdict-less on
  purpose: it demonstrates *specified* behaviour, and the property it points at is tested by example
  12's Act 8a.

### Fixed — five divergences between the specification and the reference

A clause-by-clause sweep of `spec/SPEC.md` against both kernels. §5 (canonicalization), §6 (foton
identity and the action key), §7 (claims, opaque predicates, the scope/seed grammar) and §8
(signatures, §8.1 material) came back clean. Five real divergences, plus one thing that looked wrong
and was not:

- **A malformed query parameter answered `(none)` and exited 0** — across five commands and both
  kernels. §12 says an unrecognised query parameter *"MUST be an error, never an empty result: an
  empty answer to a malformed question is a successful wrong answer."* That sentence described the
  behaviour exactly. A script asking who produced a result, with a typo in the hash, was told nobody
  had, and carried on. `plankton producer|uses|lineage` and `nekton about|by signer` now refuse a
  parameter that is not a content address (or, for a subject, a URI).

- **A union view carried an empty `epoch`** — both kernels. A union's positions are synthetic,
  assigned per open over whatever sources were named, so a fresh epoch each time is the honest
  answer: the epoch's contract is *"if this changed, your cursor means nothing"*, and a cursor
  against a union means nothing on the next open anyway. An empty one was neither "same" nor a usable
  "different".

- **`plankton producer|uses|lineage --json` returned summaries, not records.** §12 says the record
  queries answer `{records: [<envelope> …]}`; a consumer handed `{fotonId, kind, inputs, outputs}`
  cannot verify a signature or re-derive the id, and has to come back for the record it was just told
  about. Each element now carries its `envelope`; the summary fields stay alongside it.

- **§15.6 contradicted §7 and §9.** It required a conforming implementation to *"refuse … ill-formed
  reproduction claims lacking a level"*. §9 assigns that to a conforming **consumer**, and §7 forbids
  the kernel from doing it — predicates are opaque, and refusing a `reproduces` claim for lacking a
  level needs exactly the vocabulary knowledge §7 says a kernel MUST NOT require. The implementation
  follows §7; the clause was wrong and now says whose duty it is.

- **§11's "a verdict MUST carry its corpus" had no subject.** Nothing implements it, and nothing
  should: a verdict belongs to a gate or a reviewer, not to a kernel that has no verdicts and treats
  the predicate as opaque. Stated, so an implementer stops looking for it.

- Annex **C** sat between **A** and **B**; reordered.

Not a defect, checked and cleared: §15.2 names an exact foton id and action key that appear nowhere
in `reference/testdata/`. They are *derived* from `foton.dsse.json` rather than stored, and
`TestGoldenVectors` asserts both and passes.

**Left open deliberately:** `nekton about --json` answers a bare array where §12 says
`{records: […]}`. The wrapper cannot be added without breaking `claude-science-cockpit`, which parses
that array today. Filed rather than changed unilaterally.

### Fixed — `nekton verify` said yes to records `add` refuses

`verify`'s exit 0 is documented to mean *"this claim is genuine AND storable"*. It answered only the
first half.

The structural check sat inside `if st, _, perr := claim.ParseEnvelope(env); perr == nil { … }`, so a
payload that could not be parsed at all — duplicate JSON member names, say — fell through to
`return nil`. The command printed a clean signature verdict, **no `structure:` line**, and exited 0.
The absence of a line was the only signal, and no automation reads an absence. `add` refused the same
file outright:

```
$ nekton verify duplicate-members.dsse.json k.pub
signature:       VALID - verified as keyid 790901b82a89fe50
$ echo $?                                            # was 0; `add` rejects this file
```

A parse failure is now a structural failure: exit 3, with the reason printed. So is a predicate that
will not parse, whose error was being discarded into `_`.

**And the seed rules moved to where both commands can see them.** The second case was a
scope/v0 seed carrying `genesis:false`: it parses, so `verify` said `structure: VALID`, and `add`
refused it. The rule lived *only* in the registry's chain check, and `verify` never reaches a
registry. The context-free part of §7.4 — where `genesis` may appear, that a seed carries no `prev` —
is now `claim.ValidateChainStructure`, called from **both** the registry and `verify`. Two copies of
a rule is how two commands come to disagree about what a storable record is.

What stays with the registry is what needs registry state: whether a scope resolves, whether a `prev`
links to something present. That split is the point: a shared validator is worth having where the
rules are context-free, and moving a context-dependent check into one would break it.

### Fixed — a DNS rebind in `kton fetch`, and no native test on two shipped platforms

- **`kton fetch` followed a DNS rebind.** `checkDestination` resolved the hostname, and the
  `http.Client` then resolved it **again** on its own — two lookups with nothing tying them together,
  so a resolver answering a public address to the check and a loopback address to the connection
  bypassed `--allow-local` without it ever being passed. A hash check afterwards does not help: the
  request has already been made, and making the request *is* the exploit against a metadata service
  or an internal host.

  The previous release note said this "leaves with #103". That was a deferral dressed as a
  mitigation: `kton fetch` **ships in 0.2**, so the binary in the archive had the bypass whatever a
  future issue says. Fixed here instead. The name is resolved once, every address it returns is
  checked, and the connection is made to a checked address **as an IP literal** — there is no second
  lookup for a second answer to come back from. TLS still verifies against the URL's hostname.

- **CI never ran on two of the five platforms we publish.** `release.yml` ships linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64; every CI job ran on ubuntu. A packaged
  target with no passing native baseline is a claim nobody checked, and it was hiding two real
  failures — a test-setup bug that built a directory name out of an absolute path (a drive letter
  produced `...\reg\C::`), and one that matters:

  **A private key file asks for `0600` and gets `0666` on Windows.** Every statement this project
  makes about a private key being unreadable by other users rests on that mode. `WriteKeyFile` now
  **verifies** the mode after writing rather than assuming the platform honoured the request, reports
  the shortfall to its caller, and `keygen` prints a warning naming the mode it actually got — at the
  one moment the operator can still act on it. Implementing Windows ACLs would need
  `golang.org/x/sys`, and the kernels carry no third-party dependencies; what changed is that the
  protection is now checked instead of asserted. A new `platforms` job builds and tests natively on
  windows-latest and macos-latest.

### Fixed — a gate that proved nothing, a keygen that deleted keys, and two false answers

- **The security gate printed PASS having executed nothing.** With the binaries absent from
  `PATH` every one of the sixteen gated attacks reported `N-A`, `N-A` was accepted in the GATED list
  as though it were a pass, and the gate ended with *"every finding recorded as fixed is still
  PREVENTED"* and exit 0 — a security claim over zero executed proofs. Worse, the banner added days
  earlier **already printed "NOT ON PATH" three times**: the evidence was on screen and the verdict
  ignored it, which makes a hollow run look thorough.

  Prerequisites (`plankton`, `nekton`, `kton`, `jq`) are now checked before a single verdict is
  printed, and a missing one refuses to produce a verdict at all. `N-A` in the gated list is no
  longer a pass: the only honest reason left is the companion checkout, so those attacks report
  **NOT RUN** and the gate ends `INCOMPLETE`, naming how many of its proofs actually executed.
  `KTON_GATE_STRICT=1` — now set in CI — makes missing coverage fail the build, and CI's
  kton-examples checkout is no longer `continue-on-error`: two gated attacks can only run against it,
  and a fixture allowed to fail silently is the same defect one level up. With it present the gate runs
  **16 of 16** rather than 14.

- **`keygen` deleted a private key it had never written.** `WriteKeyFile` returns success for a
  file that already holds exactly the requested key, so the caller could not tell *I created this*
  from *it was already here* — and on a failure writing the public half it removed `name.key`
  unconditionally. Re-running `keygen` over an existing identity whose `.pub` had drifted therefore
  destroyed the private key, while printing *"refusing to overwrite an identity"* and *"would destroy
  the only copy of that private seed"* in the same breath. The message described a protection that
  was not there.

  `WriteKeyFile` now returns a `KeyWrite` saying what it did — created, or renamed a previous file
  aside — and `Undo` reverses only that. A pre-existing key is left alone; a half-written pair is
  rolled back; a `--force` replacement that fails restores the original from its backup. Four cases,
  four tests, in both kernels, verified to fail against the old code.

- **`reproduces` claimed a byte-identity match between two malformed strings.** Hash
  normalization was attempted and its failure ignored, so `reproduces not-a-hash not-a-hash --json`
  answered `{"level":"L0","matched":true}` with exit 0. L0 means *the same output bytes*; neither
  argument named any bytes. Both compared arguments must now normalize. Equivalent spellings — bare
  hex, uppercase, surrounding whitespace — still compare equal, which is why normalizing happens at
  all.

- **`seed --parent` signed a reference its own parser cannot read.** It emitted the *subject*
  shape, `{"digest":{"sha256":…}}`, while `claim.Ref` reads `{hash?, uri?}` (nekton SPEC §7.4:
  `parent?: Ref`). A seed authored with `--parent` round-tripped to an empty `Hash` and an empty
  `Parent.Key()`: the scope hierarchy the operator asked for was signed into a permanent claim id in
  a form nothing could interpret. Now emits `{"hash":"sha256:…"}`, normalizes the argument, and
  refuses one that is neither a content hash nor a URI. The test asserts the round trip through the
  public parser, not the shape of the JSON — a test that merely grepped for `"hash"` would pass on
  output nothing can read.

- **`cursor-shift` was crying wolf** (found while re-running the gate). Its nekton half grinds a
  scope id that sorts below an existing one, and used a **random** key — so whether the precondition
  could be built in 60 attempts was luck, and a failure to build it was counted as a miss and
  reported **VULNERABLE**. A PoC that flakes into a false REGRESSION costs exactly the attention a
  real one needs. The key and timestamps are now fixed, so the ids are identical on every machine and
  every run, and an unbuildable precondition reports `INCONCLUSIVE` — *I could not set up the attack*
  and *the attack worked* are different answers.

### Fixed — the kernel reported a verification verdict it is forbidden to have

- **`material --json` emitted `"verified": false`, in both kernels.** SPEC §8.1 defines
  `VerificationMaterial` as **four** fields and says outright *"The kernel MUST NOT interpret or
  verify `material`"* — so the JSON projection added a fifth field asserting exactly the posture the
  clause denies it. The value was a constant, so it carried no information, and it carried the wrong
  one: a consumer reads `verified: false` as **checked and failed** when the truth is **nobody
  looked**. One word, two meanings, in the field a cockpit is most likely to key on. Removed; the
  four fields of §8.1 and nothing else.

  Found by a cockpit implementer building against this surface, before 0.2 froze it. After a release
  it would have cost a migration note instead of a line.

- **The test that should have caught it could not fail.** nekton's material CLI test read the field
  into a `bool` and asserted it was false — against a hardcoded `false`. It now asserts the **key
  set** against §8.1's four fields, which fails when a fifth appears (verified both ways). plankton's
  `material --json` had no test at all; it has one now, covering a listed scheme and a carried
  unknown one.

- **SPEC §8.1 now states the read-path boundary** rather than leaving it to be inferred. A kernel
  does not verify material when it stores it and does not verify it when it hands it back:
  **presence is not a check.** Whatever verification happened, happened in some tool at some earlier
  moment under a trust configuration the kernel neither recorded nor can reproduce. The clause also
  says what a kernel's output must not contain, and points a consumer that *does* evaluate evidence
  at a three-way vocabulary — *verified here* (naming who checked), *carried*, *failed* — because a
  single boolean cannot hold those three apart.

### Fixed — six divergences between the specification and the reference

All **103** normative statements in `spec/SPEC.md` were checked against the reference. Ninety-seven
held; six did not, and each is closed on the side that was actually wrong.

- **`reproduces --via` did not surface the consumer's obligation in `--json`** (§9). The human line
  did; `--json` did not — and `--json` exists precisely so a machine consumer stops parsing prose. An
  L1 (normalized) match is only valid if the normalizer is **itself** L0-qualified; a consumer that
  never sees that requirement treats L1 as settled. Now emitted as `consumerObligation`, carrying the
  clause, the requirement, the normalizer and the command that discharges it.
- **Five places where the spec overstated and the implementation was right.** §5.1's SHOULD to keep
  the hash algorithm identifier pluggable (it is hardcoded — now recorded as a deliberate 0.1 choice
  with its cost); §5.3's SHOULD to use a tested JCS rather than a hand-rolled one (impossible here:
  zero third-party dependencies is the property that keeps the kernels auditable and
  WebAssembly-compilable, so what stands in for "tested" is now named — the frozen §15 vectors, a
  `canon(canon(x)) == canon(x)` fuzz target, and the RFC 8785 example set); §6.5's `EnvData`, defined
  but unimplemented and, unlike `meta`, not marked reserved (now **RESERVED at 0.1**); and §12's
  demand that ingest "always advance the peer cursor", asked of kernels that do not sync at all — now
  stated as a duty of the party that **pulls**, which is who holds the cursor.
- **A cross-reference that pointed at nothing.** §5.3 claimed the string-for-precision rule was
  "called out where plankton/nekton fields are defined". It was not — one occurrence in the whole
  document. The honest options were to delete the claim or to write the callouts; deleting it would
  have been the cheaper lie, because a measurement really can enter a record at exactly two places.
  §6.1 now carries the rule for a `FileRef`'s `meta` (non-covered, so no identity protects it from a
  lossy round-trip) and §7.2 for a claim's `object` Literal — where the stakes are highest, since a
  claim id is `sha256(canon(Claim))` and a rounded value would be **signed**, leaving the claim
  attesting to a number nobody measured.

### Fixed — the `envtally-CF2` proof can finally decide something

- It had **two** reasons it could never run its own scenario, and both had to go before it could say
  anything. The `EXDIR` pointing at its own directory was the first (fixed earlier); the second was
  that it passed `fit.dsse.json` as a fourth argument to `release.py`, whose contract is
  `ttl trig query FIT_HASH HEAD_HASH`. So `fit_hash` was the **filename**, the gate was bound to a
  submission that does not exist, and not one condition could light whatever the graph said.

  It now runs **two** scenarios over the shipped gate — an honest 3/3 and a forged one — because
  "the attack did not light it" and "this branch never lights" are indistinguishable without the
  control. The honest one lights; the forged one lights too:

  ```
  CONTROL  foton 3/3, claim 3/3  ->  [x] the fit's environment is qualified
  ATTACK   foton 2/3, claim 3/3  ->  [x] the fit's environment is qualified
  ```

  `release.rq`'s `FILTER(?nful = ?ntot)` compares the numbers **in the qualification**, which its
  author writes; the verdict recorded inside the cited fulfilment foton is never read. The gate's own
  comment says the forgery is caught by a re-run in Act 8a — so the guarantee is real but lives
  outside the gate, while the checklist line reads as though the gate verified it. Filed as
  gitmick/kton-examples#14.

  Recorded **OPEN** and VULNERABLE, not gated: it is a property of the shipped example gate, not of
  the kernels, which record the 2/3 verdict faithfully.

### Added — properties, not just examples

- **Fuzz targets over the canonicalization boundary**, and a CI job that actually searches (30 s per
  target) rather than only replaying the seed corpus. There were no `Fuzz` entrypoints at all, and
  what makes that matter is a whole class of numbers where `canon(canon(x)) != canon(x)` — which no
  example-based test would have found, because they all used values someone had already thought of. Measured locally at **1.48 M executions, 406 new
  interesting inputs, no failure**.

  The job is separate from the main gate deliberately: a find is *not* a regression in the pull
  request's own code, and a red mark in `verify` would say exactly that.

- **Sync convergence as a property** (nekton). §12's cursor makes one promise — follow it and you
  lose nothing — and the failure mode it has to exclude is one where a full rescan recovers what an
  incremental follow cannot. The test drives the interleavings that broke it (a co-signature arriving
  after the peer is past the claim; a chain whose seed arrives late) and asserts the **consumer's
  final state**: a peer that only ever followed cursors must hold exactly what a peer reading from
  zero holds. Verified against the pre-fix behaviour, where it reports

  > the cursor-following peer holds 4 claims, the full-read peer 5 - following the cursor lost
  > something a rescan would have found

### Changed — guards and housekeeping

- **The architecture guard now enforces that the kernels open no socket** (#104). It checked
  `net/http` only, so a kernel could have grown a network dependency through bare `net` (which dials
  one directly) or `crypto/tls` (which wraps one) with the guard green. It now covers both, plus
  `net/url`. The cockpit *may* reach an address — that is what it is for — but the files that do are
  named in the guard, so growing that surface is a deliberate act visible in a diff. Verified to fail
  in both directions.

- **CI checks `gofmt`.** Nothing did; two files sat unformatted on `dev` for weeks.

- **A truncated verification-material file is reported, not swallowed.** `bufio.Scanner` stops at the
  first error and reports it only through `Err()`, which neither reader checked — one line longer
  than the 16 MiB buffer ended the loop silently and every attachment *after* it disappeared, the
  file reading as though it had simply ended. §8.1 keeps material from affecting a record's validity,
  and it still does; what was wrong was losing evidence without a word. Both readers now say the file
  is incomplete, and still return what they could read.

- **nekton's `SetPeerCursor` takes the lock plankton got in #77.** `peers.json` is one file every
  mirror mutates, so two concurrent mirrors lost one another's cursor — and a lost cursor is a
  silently re-fetched or silently *skipped* range. Merged by maximum under the lock and written
  atomically, so a cursor only ever moves forward.

### Fixed — documentation honesty

- **`docs/federation.md` named a federation client that was deleted** (#128). The line said the
  reference implementation "has a federation **client** (`kton mirror`) and **no server**". Half of
  that has been false since #101: `kton serve` went in #83, the HTTP client went with #101, and what
  `kton mirror` dispatches to today overlays a peer registry on the **local filesystem** by hash.
  Restated precisely rather than sweepingly — the kernels open no socket in either direction and
  `check-import-direction.sh` fails the build if that changes, while the cockpit still makes outbound
  requests from exactly two files on record (`kton fetch`, Rekor anchoring), neither of which
  federates.

- **§8.1 no longer overstates the binding for foton ids.** It justified a *structural* binding using
  the claim case alone — `claimId = sha256(canon(Statement))`, which is exactly the payload digest.
  For a foton that is not true: `fotonId = sha256(canon(Foton))` over the covered projection, so a
  scheme signing the payload commits to the Statement that *derives* the id, one canonicalization
  away. Measured: the two digests differ. Still checkable with no outside information, but a
  derivation rather than an identity — and a consumer comparing digests without performing it finds
  they do not match. My overclaim, corrected.

- **`security/REPORT.md` no longer presents 70 dead permalinks as evidence.** They pointed at the
  archived predecessor repository, whose history did not carry over, so none of them resolves — while
  a footer claimed they "resolve for repo members". The hashes are kept as plain text, so the trail
  survives for anyone holding the archive and nothing claims to be checkable that is not.

### Fixed — the cursor contract: `sync(since)` delivers what it promises

- **A change to a record that a peer is already past now reaches it, and the feed no longer hides
  what the store holds.** Two failures, both measured, and neither was really a numbering problem:

  **A co-signature reached nobody.** The subnekton was **rewritten in place**, so nothing was
  appended, nothing got a position, and no cursor could notice. A subnekton is an append-only log
  *because in nekton the order carries meaning* (`prev`, head, seal) — rewriting an entry erased the
  record that anything had changed. A co-signature is now its own **line**, carrying the signature
  set it arrived with; the reader unions lines that share a claim id, exactly as `Add` already
  unioned a twin at ingest.

  **A deferred claim reached nobody either.** A claim whose seed or `prev` is not held is persisted
  and structurally valid — incomplete is not invalid (§11) — but it was absent from `Records()`, so
  a peer never received it *at all*; and when the dependency later arrived and it resolved locally,
  it entered the index at its **original** position, below every cursor already issued. The feed was
  hiding a record the store was holding. `Records()` now answers from the store's lines, not from
  the index: a deferred record is offered (and still answers no query here, joins no head, and
  counts toward no scope).

  A position is now issued against the **stored bytes** rather than the record's identity, so "a new
  stored thing" and "a new position" are the same event, and a re-mirror of identical bytes is
  idempotent for free. The two kernels then differ, correctly: nekton leaves the old line in place
  and appends; plankton keeps one file per record and fotons are an *unordered* set of
  content-addressed facts, so there is no order to preserve and the record simply takes the new
  position.

  `MaxSeq` now comes from the feed, not the index — it used to return a cursor that did not cover
  what had just been delivered, so a peer would have been handed the same co-signature on every
  sync, forever.

- **§12 restated.** The normative properties belong to the **cursor's guarantee**, not to the
  record: never decreases, newer-or-changed is higher, never derived from author-influenced content.
  *"Issued once"* was an implementation detail masquerading as a promise and is gone; nothing it
  guaranteed is lost. §12 also now says a participant MUST offer records it holds but cannot
  resolve, and that how a change reaches a peer is the participant's business as long as rule 2
  holds.

- **The numbering carries an `epoch`** (`sync` answers `{records, max, epoch}`). If a store's
  numbering is lost or replaced — a deleted counter, a restored backup, a rebuild — positions start
  again from the beginning and a peer holding a high cursor would sit silently above everything it
  is offered, receiving nothing, forever. A peer whose stored epoch differs MUST discard its cursor
  and resync. A comment in `ReadSeqMap` used to assert that peers "just resync"; nothing in the wire
  form made them, so that was a claim the protocol did not support.

- `co-signer-drop` measured `max(signatures per stored line)` — the storage shape rather than the
  finding, which is whether a co-signer can be **lost**. It now counts distinct signers surviving a
  mirror *and* asks `by signer` for each, which is what the finding was about.

### Fixed — boundary and identity rules

- **Canonicalization is idempotent, and the number rule is on the value rather than the spelling**. The exactness check ran only when the literal held no `.`, `e` or `E`, so acceptance
  depended on how a number was written:

  ```
  100000000000000000000   refused
  1e20                    ACCEPTED -> canonicalized to 100000000000000000000, which the same
                          canonicalizer then refused on a later parse
  9007199254740993.0      ACCEPTED and silently rounded, while the integer token was refused
  ```

  Two tests now run on every number, because neither alone suffices: the **literal**, parsed
  exactly (`9007199254740993` rounds to a double whose magnitude is exactly 2^53, so a test on the
  parsed value would accept 2^53+1 and sign its neighbour), and the resulting **value**
  (`12345678901234567890.5` is no integer literal, but its double is a huge integer whose canonical
  form the first test would then refuse). `canon(canon(x)) == canon(x)` now holds for everything
  accepted, checked over a corpus.

  **This narrows the accepted input set relative to RFC 8785**, which happily serializes `1e30`.
  That is deliberate: `9007199254740993` and `9007199254740992` serialize to the *same* bytes, so
  two records differing by one would share a content address. §5.3 now states the restriction, and
  its normative example list no longer implies `1E30` is accepted.

- **A field that would vanish before signing is refused**. Both authoring parsers decoded
  straight into structs, which destroys the evidence: Go keeps the **last** of a duplicate name and
  stops at the end of the first document. `"why":"first","why":"second"` was signed as `"second"`;
  `CanonJSON` accepted `{"x":1} {"ignored":2}` and returned only `{"x":1}`. The new
  `core.CheckJSONDocument` runs on the raw bytes — one complete document, no duplicate names — and
  plankton's foton spec additionally rejects unknown fields, so a misspelled `inputs` no longer
  disappears. The opaque `descriptor` stays fully extensible.

- **A precomputed foton id now equals the id of the record signed**. `FotonID` used the
  supplied hash strings verbatim while the signing path normalized them, so an accepted uppercase
  hash produced two different ids for one spec — a cockpit that precomputes a result id held a
  reference that did not resolve to the record it went on to sign. Both paths go through one
  normalized representation.

- **Structural foton validation is complete, and its failures are refusals**. A signed
  foton with two different hashes at the same **absolute** input path was accepted *and indexed*;
  its action key then failed to compute and the registry silently omitted the action-key index while
  leaving the record queryable everywhere else. `Validate` now checks bound-hash syntax, relative
  work-tree paths and duplicate input paths (path-only unbound slots stay legitimate), and both
  ingest and the read path refuse a record whose action key cannot be computed.

  Separately, `len(descriptor) == 0` conflated `descriptor: {}` with **no** descriptor, so an empty
  object let an arbitrary incorrect ref through unchecked and shared the bare-ref action-key
  namespace. Only `nil` is absent now; a present descriptor is hashed, empty or not.

### Changed — release and contributor plumbing

- **CI runs on `dev`, not only `main`** — a direct push to the active development branch was
  ungated; only pull requests were ever checked.

- **The gate and released binaries build on a supported Go line**. 1.22 is outside Go's
  support window, and the standard library ships inside every released binary — having no
  third-party modules does not remove toolchain maintenance. The declared `go 1.22` floor is now
  *proven* by a separate `compat` job rather than doubling as the release baseline.

- **`CONTRIBUTING` no longer tells readers to run `go test ./...` from the repo root**,
  which fails: the workspace root is not a module. It gives the per-module loop CI actually runs.

- Stale capability claims removed: the root README advertised `serve`, Annex C said the reference
  ships the HTTP federation **client** (deleted in #101), §13 said `kton anchor` cannot store a
  proof though `--store` does, and `kton/README` gave a build command from the wrong directory.

### Fixed — a union is now commutative

- **A multi-source read gave a different answer depending on argument order**. §11–§12 promise a conflict-free set union, and an operation whose result depends on the
  order of its arguments is not one. Three separate ways it did:

  | | before | after |
  |---|---|---|
  | a scoped child in A whose seed is in B | `child_first=false, seed_first=true` | held either way |
  | the same claim signed by two parties | 1 signature; which signer survived depended on order | 2 signatures either way |
  | material attached in the second source | lost (plankton: lost even to an **empty** second source) | merged from every source |

  `OpenUnion` opened `dirs[0]` normally — which *settled it alone* and **dropped**
  whatever did not resolve — and then settled only the remaining sources against that finished
  view. A's unresolved child was therefore discarded before B had even been read. Every source's
  raw records are now collected first and settled **together**, once.

  `settle` skipped a claim id it had already seen. A claim id covers the **payload**
  only, so two independent signers of identical bytes are one claim with two signatures — which is
  what `Add` already did at ingest. The union now merges them in memory (never writing: a read must
  not mutate a source), and refreshes the signer index so `BySigner` finds both. `unionSignatures`
  still refuses to merge across **differing** payload bytes, which is the point and is preserved.

  plankton allocated an empty material map for a union and never filled it; nekton kept
  only the first source's. Material is now merged from every source, deduplicated by attachment, and
  independently of settling — §8.1 says a record's validity never depends on its material, and the
  converse has to hold too.

  Regression tests walk **all six permutations** of a three-link chain across three stores, both
  orders of a co-signed twin, and material in every source position including empty and duplicate
  sources — each verified to fail without its fix.

### Fixed — identities are protected, and failed writes say so

- **`keygen` no longer overwrites an identity, and no longer inherits a file's permissions**. `os.WriteFile(path, seed, 0600)` looks safe and is not: the mode applies only when the
  call *creates* the file, so a pre-existing world-readable `alice.key` kept `0644` and received the
  new private seed. And `keygen alice` twice succeeded twice — the first seed was gone, and records
  signed with it could no longer be checked against that filename. The signatures stayed
  cryptographically valid; what was destroyed was the ability to check them.

  Both kernels now go through one shared `core.WriteKeyFile`: `O_EXCL`, so the mode is always the
  one asked for; an existing destination is refused with a message naming the fix; `--force`
  **moves** the old file to `<name>.key.old` rather than deleting it — this path destroys key
  material under no circumstances. An identical `--seed` is a no-op, so a reproducible snapshot
  re-runs without `--force`. A failure writing the public half removes the private half rather than
  leaving a keypair whose public key nobody has.

- **A mirror that cannot write now fails, loudly**. All three entrypoints reported success
  after storing nothing:

  ```
  plankton mirror <peer>      "0 new; registry holds 0 fotons"                        exit 0
  kton mirror plankton <peer> "0 new, 2 skipped"                                      exit 0
  nekton mirror <peer>        "1 unresolved (missing dependency - an incomplete chain)" exit 0
  ```

  The nekton wording was not merely vague, it was a wrong diagnosis of the only error class that
  could arrive: `Add` **persists** a claim whose seed or prev is missing and returns nil (§11 —
  incomplete is not invalid), so a missing dependency never reached that branch. Every error that
  did was permanent (unparseable, unsigned, structurally invalid) or environmental (a local write
  failure). The retry loops could therefore heal nothing, and are gone.

  `nekton/registry` gains `ErrPersist`, mirroring plankton's, so a caller can tell *"this record is
  invalid, skip it"* from *"I could not write, nothing was stored"*. A local write failure now
  returns non-zero and names the cause; a refused peer record is counted, named, and also exits
  non-zero, because a silent skip is how an incomplete mirror looks complete.

- **`nanopublish --rsa` no longer claims to have saved a key it lost**. With a path whose
  parent did not exist, the command generated an RSA key, published, printed *"generated a new RSA
  key and saved it to …"* and exited 0 — and the file did not exist, so the next run minted a
  different identity. The save's error was discarded with `_ =`. Separately, **any** read error was
  treated as "no key here" and fell through to generating a new one, so a permission problem
  silently replaced the identity that was requested. Both now fail with the reason.

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

- **`sync(since)` stops losing records** (#97). §12 always said the answer is "records with
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

- **`security/REPORT.md` was overclaiming its own coverage — in the release whose headline is that
  the security suite stopped doing that.** Its posture line said *"27/29 spectrum members fulfilled ·
  27 closed · 2 open"* over a Closed table with **24** rows, and *"10 of the 28 PoCs are executable
  and run in `check.sh`"* when **17** are executable and the gate runs **16**. Four gated PoCs
  (`cursor-shift`, `read-path-ungated`, `scope-path-traversal`, `union-across-payloads`) had no row
  in any summary table, and `cursor-shift` had no entry at all. Recounted from the directory: **27
  closed · 3 open · 2 accepted boundary, of 32**.

- **`envtally-CF2` was recorded closed and is not.** REPORT.md had it under Closed with a fixed-at
  commit; `check.sh` has it in the OPEN list because, once the PoC's path to the shipped release gate
  was repaired, the gate ticks **none** of its seven conditions — so "env-qualified stayed unticked"
  is true with *and without* the attack and decides nothing. It reports `INCONCLUSIVE`, never a pass.
  Filed as gitmick/kton-examples#14, still open. Moved to Open with the reason written down.

- **`security/check-report-counts.sh`** — new guard, run by `check.sh`. REPORT.md states counts about
  its own directory; a number in prose is maintained by whoever remembers to, which is the same
  defect this suite keeps finding in the code it attacks: a claim nothing can falsify. The guard
  recomputes attack totals, closed/open/boundary rows, executable PoCs and what the gate actually
  runs, and fails on any disagreement — including a PoC on disk that no table records. Verified to
  fail both ways (a wrong count, and an unrecorded script) before being wired in.

- **`check.sh` now prints which binaries it tested** and warns when one predates the working tree.
  Four findings read as REGRESSION during the spec audit against stale binaries in `~/bin` while the
  tree was clean. Every PoC resolves `plankton`/`nekton`/`kton` off `PATH`, so a green gate — and a
  red one — is a statement about whatever binaries happened to be there. A gate whose verdicts cannot
  be attributed to a build is not evidence.

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
