#!/usr/bin/env bash
# spectrum-launder (OPEN): Act-8a step 2 re-runs `spectrum check` but never re-executes the normalizer.
# Repro: in examples/12-submission make a covariate candidate genuinely differ (value=6.66 vs 6.00) and
# author a lying --kind normalize foton whose --out is the reference canon -> spectrum check 3/3 ->
# RELEASE: COMPLETE on an unqualified env. FIX (pending): mirror the step-1 fix (re-execute the
# normalizer per normalized member). Needs R + the example to run.
echo "OPEN: fix = Act-8a step 2 re-executes the trusted normalizer per normalized member (mirror step 1)"
