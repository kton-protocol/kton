# Trust: how a kton decision is honest, complete, current, and final

*Informative. Builds on the normative invariant in [`../spec/SPEC.md`](../spec/SPEC.md) Clause 11
(monotonicity and the two closed worlds) and Clause 7.4 (the sealed chain). Worked end to end in
[kton-examples 12](https://github.com/gitmick/kton-examples/tree/main/examples/12-submission).*

kton's promise is that a reader can verify a result themselves, with no central server and no need to
trust whoever produced it. This chapter is how a **decision** - a release, an approval, a sign-off -
earns that same promise, and, just as importantly, which assumptions it **names rather than hides**.
Every guarantee below is paired with the one obligation it does not discharge.

## 0. The invariant everything rests on: monotonicity

A record's **validity is intrinsic** - its hash and signature, checkable locally, independent of any
source list. Its **resolvability** - whether the things it references can be found - is relative to the
sources you read. Adding a source can only **add**: surface more records, resolve more references; it
can never make a valid record invalid or retract a statement. Contradiction is two claims, both kept;
retraction is an additive claim, never a deletion. So two readers with different source lists reach the
**same validity judgment** and differ only in what they can resolve. "Incomplete" is not "invalid."

Exactly two operations deliberately introduce a **closed world** over this open substrate, and both
carry that world **in a signature**: a **sealed scope** (a defined, not discovered, membership; Clause
7.4) and a **gate/verdict** (the only non-monotone operation). The rest of this chapter is what those
two buy, and what they cost.

**Qualification is not a third.** Tool/environment qualification asks for completeness over a spectrum's
member set, which looks closed-world - but the member set is pinned by the spectrum's own content hash
(a defined set that *travels*, not one discovered per source) and each member check is a *positive*
existence, so more sources can only *complete* a qualification, never revoke it. A not-yet-fulfilled
spectrum is *incomplete*, not *failed*. It stays monotone, and its signed `qualifies-as` acceptance
cites the spectrum-check foton so the tally is re-derivable ([example 10/12](
https://github.com/gitmick/kton-examples/tree/main/examples/12-submission)). The only way to make
qualification closed-world would be to read "partial" as "failed" - which kton does not.

## 1. Honesty and reproducibility: the decision is a foton

A gate is not a free-floating query run over some exported graph. The decision is recorded as a
**foton**: its **inputs** are the exact records it consumed (by hash), its **protocol** is the gate
logic itself (by hash), its **output** is the verdict. Three things follow:

- it is **content-addressed and reproducible** - re-run the gate over the same inputs and you get the
  same verdict (L0), exactly as any computation reproduces ([example 03](
  https://github.com/gitmick/kton-examples/tree/main/examples/03-reproduce));
- it **names its own evidence set** - "which records were used, and which were not" is simply the
  foton's input list;
- a consumer does not trust the producer's verdict; they **re-derive their own** verdict-foton over the
  sources *they* chose.

This is why a verdict must carry its corpus: because the gate is the one non-monotone operation, one
more source can surface a reject and flip pass to fail. **A verdict without its corpus is a
configuration, not a statement.**

### The general form: carry your closure

The corpus is the first instance of one rule:

> **A closed-world judgment must commit, inside its own signed payload, to every parameter that defines
> its closure - or it is re-runnable with a friendlier parameter for a friendlier answer.**

Three parameters define a gate's closure, and each is shoppable if it is not carried:

- **corpus** - else run over a subset that omits the reject (this section);
- **latest anchored head** (freshness, section 3) - else present an older, cleaner prefix;
- **trust root** (identity: which authorities' vouchers you accept) - else run with an authority who
  vouches for the clique.

Each is the *same* COVERED move: the parameter is an input of the verdict-foton, so a run with a
different value is a different foton id and cannot be passed off as this one. The trust-root instance
matters because "an enrolled participant" (section 2) presupposes an authority that says who is
enrolled; that authority set is a closure parameter, and it travels COVERED in the verdict
([kton-examples 12](https://github.com/gitmick/kton-examples/tree/main/examples/12-submission) carries a
`trust-root.txt` input).

## 2. Completeness: an open review with enrolled participants

Completeness is not "no reject exists anywhere" - undecidable in a federated world - but "every
**enrolled** participant delivered," which is decidable. A review scope ([example 05](
https://github.com/gitmick/kton-examples/tree/main/examples/05-review-scope)) is seeded to open the
review and enrol the required participants as slots; each delivers a closing (approve or reject); the
head seals only when every enrolled slot has delivered. Because the chain is tamper-evident, a
delivered reject cannot be dropped without breaking the head - a missing decision reads as
**incomplete**, never as pass-by-absence.

> **Named boundary - enrolment authority.** This is complete *given a legitimate enrolment*. Who is
> authorised to seed the review and declare its required participants is a signed **authority** claim
> (the authority-backed identity tier, [example 07/08](
> https://github.com/gitmick/kton-examples/tree/main/examples/07-identity)), not a hash or a chain. The
> dependency is surfaced, not buried in the query.

A count of distinct signing keys is **not** a count of reviewers: one actor can generate N keys and
self-issue - or ring-sign, so there is no self-loop to detect - N `sec:controller` bindings. So a gate
must not count keys; it must **join each approving key, through a binding signed by an authority in its
own trust root, to a distinct principal**. A binding is only worth the authority that signed it. This is
now mechanical in [kton-examples 12](
https://github.com/gitmick/kton-examples/tree/main/examples/12-submission): the release gate rejects a
sock-puppet ring (0 authority-vouched reviewers) and the graph viewer marks self/ring-signed bindings
unattested. The residual boundary is narrower than before - a *sealed* enrolment that also fixes *how
many* principals are required and closes over their set - but the identity-is-not-key-count half is
closed, and its trust-root parameter travels COVERED (above).

## 3. Freshness: the latest *anchored* head, not merely a valid one

A hash chain proves the **integrity** of a head, never that it is the **current** one - an earlier,
shorter chain verifies just as cleanly (a rewind). Two mechanisms close this:

- the review's **enrolment** defeats the naive rewind: an earlier head where an enrolled participant has
  not yet delivered reads as incomplete, not clean;
- **anchoring** the sealed head in a transparency log (Rekor, via `kton anchor`; [example 08](
  https://github.com/gitmick/kton-examples/tree/main/examples/08-sigstore-github)) defeats the harder
  case: the scope id resolves to its latest anchored head, so a stale head is detectable and a forked
  scope is either not of record or **visibly co-anchored** (equivocation becomes detectable).

The verdict-foton takes the **anchored head and its anchor time** as an input, so the decision commits
to "evaluated over the head current at T."

## 4. Finality: finality-as-of-T; reopening is a forward amendment

A verdict is valid **forever** as a statement about its inputs - "over head H, the gate returns
COMPLETE" is a permanent fact, never invalidated. What is time-relative is its **standing**: it is the
decision of record only until a newer anchored round supersedes it. New evidence never rewrites the
sealed head; it opens a new round carrying a forward `supersededBy` link - exactly a data-cutoff
followed by an amendment.

Whether a reopen is honest or a fault is **decidable from anchor timestamps**: evidence anchored *after*
T means the decision was sound and is merely superseded (an amendment); evidence anchored *before* T
that was omitted means the decision was defective (a rewind, or an illegitimate enrolment).

> **Named boundary - the consumer freshness check.** The log guarantees a reopen is undeniable and
> time-ordered: the new evidence exists, is anchored, and cannot be backdated or hidden. It does not
> guarantee the consumer *notices*. So a decision is relied upon only after confirming it is the latest
> anchored head for its scope as of reliance time - a consumer obligation. What the log provides is that
> a missed reopen is **negligence, not ignorance**: "I didn't know" becomes the checkable "I didn't
> look."

## 5. Verification is two operations, and a graded ladder

Verifying the **record** - its signature (who signed), its id (integrity), and the shape of the lineage
it joins by hash - needs only the record itself. It works offline, anywhere, forever, and is exactly
what `mirror` and multi-source read distribute. Verifying the **content** - that a file really hashes to
its recorded hash, or that re-running reproduces the output - needs the actual bytes, which travel
separately (the git vs git-annex split). Verification therefore **degrades gracefully**: with no bytes
you still hold a fully verifiable skeleton of who-claimed-what; the bytes add content truth on top.

So assurance is a **ladder**, and a verifier chooses the rung the situation demands rather than
re-running everything:

| Tier | What it proves | Needs |
|---|---|---|
| **record-authentic** | signature + id ([example 01](https://github.com/gitmick/kton-examples/tree/main/examples/01-hello-foton)) | the record only - always available |
| **content-present** | the bytes hash to the recorded hash (fetch via a signed `dcat:downloadURL`, re-hash) | byte availability |
| **reproduced** | re-run in a qualified environment ([examples 03/10](https://github.com/gitmick/kton-examples/tree/main/examples/10-tool-spectrum)) at L0/L1 | bytes + an executor |

> **Named boundary - retention.** Byte availability is a **liveness** property the hashes do not
> provide: records are kept forever and cheaply; bytes are kept per retention policy, and **located, not
> stored** in the registry. Availability is never a *trust* problem - content addressing self-checks on
> arrival (`sha256 == hash`), so a location is a hint, not an authority: bytes may come from any mirror,
> including an untrusted one, and corruption is detected. What the system does not guarantee is that the
> bytes still exist somewhere; that is a retention obligation, stated rather than assumed.

## The three boundaries, together

Everything above is guaranteed by hashes, signatures, and chains. Exactly three things are not, and each
is surfaced as an explicit obligation rather than hidden in a query:

1. **enrolment authority** - who may open a review and name its participants (a signed authority claim);
2. **the consumer freshness check** - confirming you hold the latest anchored head before relying;
3. **byte retention** - that the located bytes still exist somewhere.

That the substrate can state its own three assumptions this precisely - and no more than three - is the
point: honesty, completeness, freshness, finality, and graded verification are mechanical; the rest is
named.
