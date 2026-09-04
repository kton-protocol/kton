# The scope question

*Written for a discussion, not as a conclusion. Status: open (#70, #10).*

The repository states its scope twice. That is not obviously wrong — the two statements answer
different questions — but one of them has legal effect, they have already drifted apart once, and
the boundary between them is not written down anywhere. This is the material for working through
where the line actually falls, using cases rather than principles.

---

## 1. What the two documents are

| | `spec/SPEC.md` §1 | `community-specification/02-scope.md` |
|---|---|---|
| **what it says** | what *this document* specifies | what the *patent commitment* covers |
| **who reads it** | an implementer deciding what to build | a licensee, a contributor, a court |
| **form** | an ISO-style Clause 1 | the Community Specification License's Scope |
| **effect if wrong** | someone builds the wrong thing | the commitment covers more or less than intended |

They overlap deliberately and heavily. Almost everything in scope for one is in scope for the other.
But they are not the same sentence, and the cases below are where they come apart.

## 2. The open legal question, first

License §9.13:

> "Scope" has the meaning as set forth in the accompanying **Scope.md** file included in this
> Specification's repository. … **If no Scope is provided, each Contributor's Necessary Claims are
> limited to that Contributor's Contributions.**

There is no `Scope.md` in this repository. There is `community-specification/02-scope.md`.
`getting-started.md` says three times to "complete the Scope.md file".

Everything below assumes that question gets answered. It is not a technical decision and nothing in
this document resolves it.

---

## 3. Cases

These are the ones that actually decide the shape. Each is a real thing kton either does or has been
asked to do.

### 3.1 Canonical JSON

Uncontroversial and worth stating as the baseline. It is in scope for both: the spec defines the
exact bytes, and the patent commitment covers them. Two implementations that disagree here compute
different identities, so it is the one place where "interoperable" and "patent-safe" have to mean the
same thing.

**No tension.** Both documents say it. Nothing to decide.

### 3.2 A signed PDF of a claim

Currently **out of scope in both** — added recently, and the reason is stated: a signed PDF signs a
*rendering*, and the relationship between that rendering and the record's canonical bytes is not
content-addressed.

But consider what that means for a licensee. Someone builds a regulated workflow where the auditable
artefact *is* a PDF, carrying a qualified signature, with the claim id printed inside it. They are
implementing the specification faithfully — the PDF is a §14 projection with an explicit provenance
reference, which the spec describes. Is their PDF renderer within the patent commitment?

**Under the current text, no.** The renderer is out of scope. Whether that is the intended answer is
the question: it is defensible (we do not want to commit patents over document formats) and it is
also the case a pharma implementer is most likely to hit.

### 3.3 Verification material — the §8.1 attachment point

In scope for both, as of the recent change. But notice how narrowly.

The **shape** — `{subject, scheme, mediaType, material}`, bound by content address — is in scope.
The **evaluation** of any material is explicitly out. So:

- a library that stores a Sigstore bundle against a claim id: in scope
- a library that checks the bundle's Fulcio certificate against a trust root: out of scope
- a library that does both, in one function: ?

The third is not a trick question. It is what every real consumer will ship. The current text draws
the line at a place that no single program will respect, which may be correct (the commitment
follows the *specified* surface, not the program) or may be a sign the line is drawn in the wrong
place.

### 3.4 The federation endpoints

§12 defines a minimum federation surface — `claims?subject=`, `claim?id=`, `sync?since=` and so on —
and §15 makes serving them a conformance requirement. Meanwhile §1 puts "specific transports and
hosting (git, GitHub, HTTP…)" out of scope.

So a **required** surface is expressed in terms an out-of-scope transport. The intent is clear
enough — the *semantics* of the queries are in scope, HTTP is one binding among several — but the
text does not say that, and someone reading only §1 would conclude the endpoints are not covered.

**This one is probably just a wording gap** rather than a real boundary question. It is here because
it is the easiest to get wrong when editing either document.

### 3.5 The reference implementation

Out of scope in both, licensed separately (Apache-2.0). Clean, and worth keeping clean.

But the specification cites the reference implementation as normative in one place: §15 conformance
requires reproducing the frozen vectors in `../reference/testdata/`. The vectors are *in* the
out-of-scope tree.

That is not a contradiction — data is not code, and the vectors are the specification's own
conformance fixtures that happen to live there — but it is the kind of thing worth being deliberate
about rather than discovering later. Moving the vectors under `spec/` would make the boundary
cleaner at the cost of a lot of churn.

### 3.6 eIDAS / a qualified electronic signature

Not currently mentioned in either document except as an out-of-scope signing backend.

If kton later says something normative about *how* a qualified signature attaches — a required
`scheme` token, a required binding, a required refusal — that statement is in scope, while the QES
itself and its evaluation are not. Same split as 3.3, and the same question: is that line stable, or
does it move the moment the specification says anything a QTSP has to satisfy?

Worth deciding **before** anything is written, not after.

### 3.7 Something the specification does not mention at all

The hardest case, and the reason the two documents cannot simply be merged.

`02-scope.md` describes the Working Group's scope — what it *develops*. `spec/SPEC.md` §1 describes
what the current document *contains*. A topic the Working Group intends to specify but has not yet
written is in the first and, correctly, absent from the second.

Today there is no such topic, so the two lists match. The moment there is one, they must not.

**This is the argument against the merge**, and it is structural rather than legal: a patent
commitment that only ever covers what is already written is a commitment that shrinks to nothing
whenever the specification is behind its own intent.

---

## 4. What the drift check does and does not do

`scripts/check-scope-drift.sh` compares invisible keys (`<!-- scope:in KEY -->`,
`<!-- scope:out KEY -->`) carried by each item in both documents, and fails CI if the key sets
differ. Verified to fail in both directions.

It catches the thing that actually happened: an item added to one file and not the other.

It does **not** catch a topic that belongs in the Working Group's scope but not yet in the
specification's — case 3.7 — and by design it cannot, because that asymmetry will one day be
correct. If 3.7 ever becomes real, the check needs a way to mark an item as "Working Group only",
and that marker is itself a decision about what the commitment covers.

---

## 5. Questions to settle

1. The `Scope.md` filename question (#70). Everything else waits on it.
2. Does the patent commitment follow the **specified surface** or the **shipping program**? Case 3.3
   makes them differ, and every real consumer sits on the wrong side of the line.
3. Is 3.2's answer — a compliant PDF renderer is outside the commitment — the intended one?
4. Should §12's minimum federation surface be restated in transport-neutral terms, so a required
   surface stops being described in out-of-scope vocabulary? (3.4)
5. Do the conformance vectors move under `spec/`? (3.5)
6. When the Working Group's scope first runs ahead of the document, how is that expressed — and how
   does the drift check learn about it? (3.7)
