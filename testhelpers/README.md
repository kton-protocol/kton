# testhelpers/ - executors for tests & the lab (NOT the kernel)

A **potential** is a recipe; it needs an **executor** to be *applied*. Executors run - so they are
never part of the plankton/nekton/kton core packages (which document, compare, and federate, but
never execute). They live here, as ordinary programs a test or a cockpit invokes.

- `normalize` - a **bash normaliser-executor** that realises a strip-pattern potential (e.g.
  `../potentials/strip-license-date.recipe.json`): it reads the recipe + an input file and writes
  the canonical (normalised) form. Because it runs, it must itself be qualified at L0 (byte-exact
  re-run) before it can be trusted to normalise outputs used to qualify other tools.

Typical use - produce the normalisation ray a `plankton spectrum check` then compares by hash:

```
testhelpers/normalize potentials/strip-license-date.recipe.json ref.lst ref.norm
plankton author --in ref.lst --out ref.norm --cmd "normalize strip-license-date" \
    --kind strip-license-date --sign k.key -o ref.norm.foton.json
plankton add ref.norm.foton.json
# (same for the candidate) then:
plankton spectrum check <tool>.spectrum.json --candidate <ref>=<cand-output-hash>
```

For now this is bash; a real executor (any language) realises the same recipe identically. The
recipe is the definition; this is one realiser of it.
