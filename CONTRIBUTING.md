# Contributing to Sentinel (Enterprise Pipeline)

We welcome contributions to the Sentinel project! As a Governance-Driven Security Pipeline, Sentinel maintains strict compliance boundaries to ensure zero false positives and high-trust heuristic detections. Please read these guidelines to ensure your modifications are accepted smoothly.

## 1. Local Development Feedback Loop

To guarantee rapid execution and minimize Developer friction, Sentinel employs a split-tier CI validation architecture:
- **Pre-commit Gates (Husky):** Every commit invokes a lightweight syntax review ("Sarb-Lite") through Node and Linting. This step provides rapid feedback and acts as your first sanity check. If you disable git hooks locally (`--no-verify`), the automated Continuous Integration pipeline will still intercept regressions.

## 2. Benchmark Enforcements

Sentinel is protected by an unskippable "Benchmark Pipeline" `scripts/benchmark_suite.js`. Any modifications you make to the Adaptive AST engine, Static Patterns, or JSON serialization formats must be validated against the suite:

1. Use `npm run benchmark` before pushing to `main` or opening a PR.
2. The Benchmark isolates clean workflows (`gh_bridge.js`) to assert that the **False Positive Rate remains at 0%**. Spikes in False Positives will be automatically hard-blocked natively.
3. The Benchmark simulates Evasion Malware (e.g. Obfuscated Base64 Eval Triggers) to ensure that the engine continues to achieve a True Positive threat response >80 score continuously. Do not diminish the mathematical detection ceilings.

## 3. Threat Governance Signatures (Rulepack Standard)

Any new vulnerability signature added to Sentinel must comply with the Operational Output Contract:
- **No Orphaned Threats:** Emitting an alert without a unified `rule_id` and `explanation` will be blocked by Sentinel's rigid local schemas.
- **Rule Identifier Namespace:** Inject findings strictly under the `SARB-[FAMILY]-[ID]` structure. (E.g. `SARB-EXEC-155` for arbitrary execution flows).
- **Rulepack Injection:** Ensure all components respect the centralized `rulepack_version` string root embedded by the central CLI orchestrator.

## 4. UI Isolation Integrity

Sentinel's UI (Replay Scanner / Virtual Boards) must remain completely ignorant of the runtime data analysis implementation.
- Your algorithms must compute Confidence Scores, Weights, and Trust Flags purely at the execution baseline / Sandbox Backend stage. DO NOT attempt to "calculate" logic inside React frontends. React only serves as a forensic, JSON-agnostic representation of your findings.

Following these practices ensures Sentinel stays enterprise-ready and stable over the years. Thank you for making security pipelines safer!
