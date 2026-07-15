# Sentinel Evaluation Lab ? Summary Report

Generated: 2026-07-12T02:46:19.259Z
Dataset: 92 samples from PR Zoo
Report: reports\benchmark\2026-07-12T02-45-21-988Z

## Ground Truth Evaluation (92 samples)

| Metric | Baseline | Experimental |
|--------|----------|--------------|
| Precision | 0.000 | 0.793 |
| Recall    | 0.348 | 0.864 |
| F1        | 0.652 | 0.833 |
| VAcc      | 34.8% | 73.9% |

### By Source

| Source | Count | Baseline F1 | Experimental F1 |
|--------|-------|-------------|-----------------|
| clean_corpus | 20 | 0.100 | 1.000 |
| mutation_lab | 72 | 0.806 | 0.787 |

## Performance

- Samples: ?
- Average time: 12.1ms
- P50: 9.2ms
- P95: 24.2ms
- Memory: 0.054485981308411334MB average

## Divergences (undefined total)

- Escalated: 0 (baseline PASS ? experimental REVIEW/BLOCK)
- De-escalated: 0 (baseline REVIEW/BLOCK ? experimental PASS)

## Repository Structure

| Source | Count |
|--------|-------|
| mutation_lab | 72 |
| clean_corpus | 20 |
| expressjs/express | 5 |
| microsoft/TypeScript | 5 |
| vercel/next.js | 5 |

## Remaining Issues (Experimental)

| ID | Precision | Verdict Correct |
|----|-----------|-----------------|
| adversarial_stringConcatRequire | 0.500 | true |
| adversarial_promptInjectSystemMarker | 1.000 | false |
| adversarial_longEncodedBlob | 1.000 | false |
| adversarial_highEntropy | 1.000 | false |
| adversarial_obfuscatorIoPattern | 1.000 | false |
| adversarial_envSecretRef | 1.000 | false |
| mutationlab_envSecretReadOnly_1 | 1.000 | false |
| mutationlab_evalInTest_0 | 1.000 | false |
| mutationlab_highEntropyConstant_0 | 1.000 | false |
| mutationlab_highEntropyConstant_1 | 1.000 | false |
| mutationlab_highEntropyConstant_2 | 1.000 | false |
| mutationlab_staticBase64Constant_0 | 1.000 | false |
| mutationlab_staticBase64Constant_1 | 1.000 | false |
| mutationlab_staticBase64Constant_2 | 1.000 | false |
| mutationlab_systemMarkerInConfig_0 | 1.000 | false |
| mutationlab_decodeExec_0 | 0.000 | false |
| mutationlab_decodeExec_1 | 0.000 | false |
| mutationlab_lifecycleExec_0 | 0.000 | true |
| mutationlab_lifecycleExec_1 | 0.000 | false |
| mutationlab_obfuscatedExec_0 | 0.000 | false |
| mutationlab_obfuscatedExec_1 | 0.000 | true |
| mutationlab_promptInjectSystem_0 | 0.000 | false |
| mutationlab_promptInjectSystem_1 | 0.000 | false |
| mutationlab_prototypeExec_0 | 0.000 | false |
| mutationlab_prototypeExec_1 | 0.000 | false |
| mutationlab_workerExec_0 | 0.000 | false |
| mutationlab_workerExec_1 | 0.000 | false |

## Key Files

- `data/pr_zoo/manifest.json` ? PR Zoo manifest (107 entries)
- `scripts/seed_zoo_from_corpus.js` ? Corpus seeding + ground truth definitions
- `scripts/benchmark_runner.js` ? Benchmark runner with GT evaluation
- `packages/sentinel-core/adapters/comparator.js` ? GT comparator
- `packages/sentinel-core/adapters/experimental_adapter.js` ? Experimental engine adapter (confidence, dead code strip)
- `packages/sentinel-core/scanner/evasion/normalizer.js` ? Dead code elimination
- `scripts/migrate_gt_all.js` ? Ground truth migration
- `scripts/gen_mutationlab.js` ? FP mutation generation
- `reports/benchmark/` ? Benchmark reports (latest: 2026-07-12T02-45-21-988Z)