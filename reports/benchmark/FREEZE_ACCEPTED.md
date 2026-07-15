# FREEZE — Sentinel Evasion Detector (EVASION-023)

**Date:** 2026-07-15
**Iteration:** 5
**Decision:** ACCEPTED — FROZEN

---

## Final Metrics (162-sample corpus)

| Metric | Value |
|---|---|
| Clean accuracy | 100.0% |
| FP rate | 0.0% |
| Verdict accuracy (experimental) | 87.0–88.2% |
| Verdict accuracy (baseline) | 36.3% |
| Micro F1 | 0.678 → **no usar como indicador de producción** |
| FP clusters | FP-001..FP-007 all zero |
| Stress test (10 unseen) | 0 verdict errors |

## Why Micro F1 Is Misleading

The ground-truth in `mutation_lab` and `stress_test` sidecars uses
**semantic types** (`DECODE`, `EXECUTION`, `HARDCODED_SECRET`) while the
engine emits **technique IDs** (`EVASION-011b`, `EVASION-023`).  The
comparator maps `expected → f.type` and `actual → f.techniqueId`, so
these never intersect.  Result: TP=0 for those subsets, dragging down
precision and recall mechanically.

**Production-grade metric:** verdict accuracy + clean FP rate.
Finding-level F1 is only meaningful for the `adversarial` subset where
both ontologies agree.

## Architecture (Final)

- **heuristics.js (H15):** EVASION-023 context gate — `ctxEvidence` checks
  for decode/exec/network/filesystem co-occurrence, plus `isEncodedBlob`
  (70+ chars / placeholder prefixes) and `isTestContext`
  (describe/it/test/assert/expect).
- **patterns.js:** EVASION-023 preserved at LOW/risk 2 as stub pointing
  to heuristics.  Clean samples no longer trigger CRITICAL.

## Freeze Criterion

> Do **not** re-open EVASION-023 tuning unless a **new FP family**
> (unseen pattern not represented in the current 162-sample corpus)
> appears in production.  Do not tune by benchmark inertia.

## Artifacts

- `reports/benchmark/2026-07-15T00-23-08-902Z/` — final benchmark run
  with stress samples
- `reports/benchmark/clusters_registry.json` — FP-007 count: 0
- `data/pr_zoo/patches/stress_*.patch` — 10 stress-test samples
- `data/pr_zoo/manifest.json` — 162 entries

## What Comes Next

No further rule tuning.  Production consolidation phase.
If a new failure class appears, validate generalization first,
then consider unfreeze.

---

*cuuuuchaaaaooo*
