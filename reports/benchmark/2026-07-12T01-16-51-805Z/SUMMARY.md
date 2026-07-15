# Sentinel Evaluation Lab ? Summary Report

Generated: 2026-07-12T01:21:18.950Z
Dataset: 80 samples from PR Zoo
Report: reports\benchmark\2026-07-12T01-16-51-805Z

## Ground Truth Evaluation (80 samples)

| Metric | Baseline | Experimental |
|--------|----------|--------------|
| Precision | 0.000 | 0.863 |
| Recall    | 0.400 | 0.994 |
| F1        | 0.600 | 0.858 |
| VAcc      | 40.0% | 82.5% |

### By Source

| Source | Count | Baseline F1 | Experimental F1 |
|--------|-------|-------------|-----------------|
| clean_corpus | 20 | 0.100 | 1.000 |
| mutation_lab | 60 | 0.767 | 0.811 |

## Performance

- Samples: ?
- Average time: 7.7ms
- P50: 6.2ms
- P95: 19.9ms
- Memory: 0.009052631578947385MB average

## Divergences (undefined total)

- Escalated: 0 (baseline PASS ? experimental REVIEW/BLOCK)
- De-escalated: 0 (baseline REVIEW/BLOCK ? experimental PASS)

## Repository Structure

| Source | Count |
|--------|-------|
| mutation_lab | 60 |
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

## Key Files

- `data/pr_zoo/manifest.json` ? PR Zoo manifest (95 entries)
- `scripts/seed_zoo_from_corpus.js` ? Corpus seeding + ground truth definitions
- `scripts/benchmark_runner.js` ? Benchmark runner with GT evaluation
- `packages/sentinel-core/adapters/comparator.js` ? GT comparator
- `packages/sentinel-core/adapters/experimental_adapter.js` ? Experimental engine adapter (confidence, dead code strip)
- `packages/sentinel-core/scanner/evasion/normalizer.js` ? Dead code elimination
- `scripts/migrate_gt_all.js` ? Ground truth migration
- `scripts/gen_mutationlab.js` ? FP mutation generation
- `reports/benchmark/` ? Benchmark reports (latest: 2026-07-12T01-16-51-805Z)