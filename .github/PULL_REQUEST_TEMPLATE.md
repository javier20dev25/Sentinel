# Sentinel Enterprise PR Template

## 🛡️ Governance Compliance Checklist

*Sentinel is an auditable Governance Decision Engine. We do not accept heuristics or engine changes that break the Source of Truth.*

Before merging your changes, assert the following Governance standards:

- [ ] **Regression Benchmark:** I have executed `npm run benchmark` locally and my checks passed with Exit Code 0 (0% False Positives regression & 100% TPR maintained).
- [ ] **Rulepack Auditability:** My new feature/heuristic emits a formal `rule_id` prefix `SARB-[FAMILY]-[ID]` and a plaintext `explanation` for SOC forensics.
- [ ] **Decoupling Maintained:** I have not coupled UI data computations into raw payload generations (Sentinel UI must remain unaware of the underlying heuristic engine code).

## Summary of Changes

*Describe the security enhancement, heuristic adjustment, or engine fix this PR brings.*

...

## How to Verify
*Please offer a quick manual vector (Snippet testing) that verifies this finding triggers properly and emits its `rule_id` inside the json artifact.*

...
