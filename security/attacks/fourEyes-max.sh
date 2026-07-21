#!/usr/bin/env bash
# fourEyes-max: single reviewer / all-sponsor submission passed the OLD SPARQL four-eyes.
# Repro: in examples/12-submission, have the model author sign both gxp:reviewed=pass reviews (or one
# key bound to two principals). FIXED at kx@56ae3cd (release.py::independent_reviews counts in the driver:
# >=2 distinct authority-vouched principals, each != verified author). Needs R + the example to run.
echo "see kx@56ae3cd release.py::independent_reviews; adversarial table: single-reviewer/self-review -> BLOCKED"
