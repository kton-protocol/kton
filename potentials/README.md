# potentials/ - normaliser recipes (definitions, not executors)

A **potential** is a pure, content-addressed *recipe*: a declaration of an equivalence criterion,
independent of any program that applies it. `strip-license-date.recipe.json` says *which*
incidental lines of a NONMEM `.lst` two correct runs may legitimately differ on (license,
run date, run directory) - the criterion for **L1** identity.

A potential is a **definition**. It is *realised* by an **executor** - a program that reads the
recipe and an input and emits the canonical form (the bash realiser `../testhelpers/normalize`, or
the spike's `../spike-rcockpit/potentials/normalize.py`). Because that program **runs**, it is an
executor - never a core package - and it must itself be **qualified at L0** (byte-exact re-run)
before it can be trusted to normalise outputs used to qualify *other* tools. plankton never runs
it; it only compares the resulting fotons by hash.

This split - recipe (potential) vs. realiser (executor) - is what keeps the normaliser
**inspectable and content-addressed**: the rounding/stripping lives inside a declared, hashable
recipe, never as hidden policy. See `../docs/reproduction-identity.md` and `../spec/SPEC.md` §1 (out of scope);
a potential is referenced by a spectrum as its normaliser (see `reproduction-identity.md` §Spectrum).
