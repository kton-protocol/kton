# Scopes & seeds - the one grammar in the kernel

> **Status:** design note + normative addition to `spec/SPEC.md` (v0.1). This introduces the
> *first and only* structural grammar nekton mandates. Everything else stays opaque and federated.

## Why nekton admits exactly one grammar - and why it is this one

nekton's discipline has been: **the kernel prescribes no meaning.** Predicates and contexts are
opaque `TermRef`s; equivalence is a downstream, federated `sameAs`. That is correct for *meaning*,
which is contested and plural.

But identity and boundary are not meaning. A federated trust system has to answer, in the kernel:

- *What is "one registry"?* (boundary)
- *How do I know a statement belongs to it, and that none were removed?* (integrity, order)
- *How does one registry stand for another?* (nesting, trust transfer)

These cannot be pushed downstream, because **they are what "downstream" is defined relative to.**
If the boundary and identity of a registry were themselves negotiable claims, there would be
nothing stable to attest *about*. So the kernel must own a minimal grammar of *structure* - not of
meaning.

There is a second, deeper reason. A single DSSE signature is the **atom** of trust: one key
vouches one statement. Federated institutions need a **molecule** - a unit of trust larger than a
signature, transferred wholesale. A municipality's entire log should be trustable because the
county vouched *the municipality*, once, not because the county re-signs every ballot. The **seed**
is that molecule. It is the minimal structural object that lets trust compose across institutions
instead of accumulating one signature at a time.

So the kernel admits one grammar: **a scope is born from a seed, forms a hash-chain, and may name a
parent.** That is the whole addition. It carries no ontology; it is pure structure - identity,
order, boundary, nesting - and it exists precisely because trust-transfer-beyond-a-signature has no
downstream home.

## The grammar (normative)

### Seed - the genesis of a scope
```
Seed := a signed Statement, predicateType "https://kton.dev/scope/v0", predicate:
  { scope:        string,          # the scope's self-declared name (human label)
    parent?:      Ref,             # hash of the parent scope's Seed; omitted ONLY for a root
    responsible:  [ Identity ],    # the accountability set (see below)
    genesis:      true }           # a Seed has NO prev; it opens the chain
```
- **A scope's identity IS its seed hash:** `scope_id = sha256(canonical(Seed))`. Not the label,
  not a URL - the content hash of the genesis. Unforgeable and self-certifying.
- A Seed is the only statement in a scope with no `prev`.
- **`genesis: true` is admissible ONLY on a `scope/v0` seed.** The kernel MUST reject any
  statement that carries `genesis: true` whose predicateType is not `https://kton.dev/scope/v0`
  (and MUST reject a seed that carries a `prev`). This is the anti-forgery converse: it stops a
  non-seed statement from claiming to open a chain. (Reference: `registry.checkChain`.)

### Chain - every subsequent statement
```
each non-genesis Statement in the scope carries:
  scope: scope_id      # which scope this belongs to (the seed hash)
  prev:  Ref           # hash of the immediately preceding Statement IN THIS SCOPE
```
- The scope is a hash-chain `Seed ← s1 ← s2 ← …`. **Removing or reordering any statement breaks
  the chain** - this is the "untainted" guarantee, and it is kernel-enforced.
- The kernel MUST verify, on ingest of a scoped statement: `prev` exists in-scope, and the chain
  resolves back to `scope_id` without a gap.

### Registration - trust transfer (convention, not kernel)
Trust flows by a parent **recording a statement in its own scope** about the child:
```
in the PARENT scope:  { predicate: "registers-scope", subject: <child scope_id>,
                        ... signed by the parent's responsible set }
```
Now anyone who trusts the parent's seed transitively trusts the child's - **institutional trust,
composed.** The kernel does not enforce registration or the `responsible` rule (those are checked
by consumers / the aggregator, §below); the kernel guarantees only **identity + order + boundary +
nesting**. The seed is admitted for the *structure*; the *policy* on top stays federated.

> **The clean split, preserved:** the kernel now understands the structural fields `scope`,
> `parent`, `prev`, `genesis`, `responsible`. It still does **not** understand `registers-scope`,
> `vote-initialised`, `count-finished` as *meanings* - those remain opaque predicate terms
> (templates). The kernel enforces the *shape* of a scope; vocabularies give it purpose.

## Application: federated election aggregation

The design that motivated this. Secrecy is solved by **layer, not crypto**: the municipality is the
lowest layer because *real people physically count paper ballots there*. nekton never sees a
per-voter vote - only the municipality's **counted result**. There is no vote↔voter link in the
digital layer to protect. The whole homomorphic/mixnet problem is sidestepped by putting the trust
boundary where democracies already put it: the local count board.

### Two templates are the entire interoperability contract
- **`vote-initialised`** - *is* a scope Seed for a municipality's election: carries the seed, names
  the responsible counters as `responsible`, and the election as `context`. Known to the county.
- **`count-finished`** - the **seal**: a chained statement carrying the result, signed by **all**
  `responsible` counters, after which the chain is closed.

"Connecting a municipality" collapses to: **the county holds that municipality's seed hash.** That
single registered value is the whole trust relationship - provenance (the chain descends from *that*
seed), integrity (the chain is untainted), and completeness (the seed anchors a closed sequence)
are all checkable from it.

### The aggregating step is a reproducible validity gate (a plankton foton)
The county's result is produced by a `kind=aggregate` **executor** (a workbench, made reproducible),
whose inputs are the child scopes' seeds + chains by hash. Before emitting a county result it
**deterministically checks**:

1. **chain-from-seed** - each municipality's chain runs unbroken from its registered seed to its
   `count-finished` (integrity + provenance);
2. **all-responsible-signed** - every identity in that seed's `responsible` set signed the
   `count-finished` (authority is complete);
3. **registered** - the parent holds a `registers-scope` for each child (trust transfer present);
4. **roster-complete** - the set of children matches the expected roster; none missing, no
   duplicates.

Only then does it sum the results and emit the county foton. Because the gate is deterministic, the
**validity check itself is reproducible** - anyone re-runs it and gets the same verdict. The rules
live in the templates + the aggregator's `kind`; the guarantee is that the gate is not a trusted
script but a re-runnable computation. *That is where the art of structuring lives.*

### It recurses - a tree of seed-anchored chains
```
        state Seed
         ├─ registers → county Seed ──┐
         │                            ├─ aggregate foton  (checks 1–4, sums)
         │   county Seed              │
         │    ├─ registers → municipality Seed ── vote-initialised … count-finished
         │    └─ …                    │
         └─ …                         ▼
                              plankton records each aggregation as a foton;
                              lineage walks national number → county → municipal count board
```
- **nekton** holds the signed, seed-anchored, chained scopes.
- **plankton** records each aggregation Statement - *"a foton arrived"* - and the lineage of
  results is a foton chain from national total back to a single count board.
- **a workbench** is the executor: it runs each municipality's *validated system* and makes each
  aggregation gate *reproducible*.

Minimal infrastructure (everyone serves an append-only chained log), total transparency (every
number is a hash anyone re-runs), and the only political question left is the very top - who anchors
the state root - which is at least a single visible hash, not a hidden database.

## What this costs the kernel (honest accounting)

- nekton was, until now, a content-addressed **set**, federated by hash. It now also has a
  per-scope **order** (the seed-anchored chain). Both guarantees are wanted: set-union federation
  *between* scopes, hash-chain integrity *within* a scope.
- The kernel gains five structural fields (`scope`, `parent`, `prev`, `genesis`, `responsible`) and
  two ingest rules (genesis-has-no-prev; non-genesis-chains-in-scope). Nothing semantic.
- `responsible`, `registers-scope`, and sealing enforcement remain **conventions checked by
  consumers**, not kernel rules - keeping the kernel to identity/order/boundary/nesting only.

## Open questions

1. **Root anchoring.** Who registers the top scope, and how is that single trust anchor published
   and rotated? (The one irreducibly political point - but a visible hash, not a database.)
2. **Chain forks / equivocation.** A scope holder could sign two different `prev=X` successors
   (a fork). Detection is easy (two statements share a `prev`); the response (freeze, external
   arbitration) is policy. A transparency-log anchor (Rekor-style) on each seal helps.
3. **Responsible-set changes mid-scope.** Counters resign/substitute - model as a chained
   `responsible-updated` statement, itself signed by the outgoing set.
4. **Where `registers-scope` and `count-finished` sit** - templates (vocab) referencing the kernel
   scope fields; drafts belong in `templates/`.
5. **Should the kernel enforce `responsible` sealing**, or leave it to the aggregator gate? This
   note leaves it to the gate to keep the kernel minimal; revisit if forks make kernel enforcement
   worthwhile.
