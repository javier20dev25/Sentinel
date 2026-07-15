# Sentinel Context (Frozen)

**Status:** Production freeze — EVASION-023 tuning complete.

## Do Not
- Tune EVASION-023 rules. They are frozen.
- Chase Micro F1. It mixes two ontologies (semantic vs techniqueId).
  Use verdict accuracy + clean FP rate for evaluation.

## Do
- Add new unseen samples to `data/pr_zoo/` if a new FP family appears.
- Validate generalization before considering unfreeze.
- Run `node scripts\benchmark_runner.js` to benchmark.

## Current Numbers
- Clean accuracy: 100% (0 FPs)
- Verdict accuracy: ~88% (vs baseline 36%)
- Micro F1: 0.678 (ignore for production decisions)
- Corpus: 162 samples (10 stress_test)
- FP-007: 0

## Architecture
- EVASION-023: heuristics.js H15 (context gate) + patterns.js stub (LOW)
- All detection families at 100% coverage.
