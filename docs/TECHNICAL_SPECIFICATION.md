# Sentinel: Formal Technical Specification

## 1. Abstract
Sentinel is an auditable security decision engine designed for high-velocity CI/CD environments. It implements a multi-layered static analysis heuristic model that classifies source code anomalies into semantic risks (Security Findings vs. Policy Violations). This document details the algorithmic complexity, mathematical foundations of entropy analysis, and the adaptive gate orchestration logic.

## 2. Theoretical Framework

### 2.1. Intent-Based Heuristics
Unlike signature-based antivirus solutions, Sentinel's core engine (SARB) operates on a **Signal Composition Matrix**. Each signal $s_i$ carries a weight $w_i \in [0, 100]$. The final risk level $R$ for a given file is calculated through a logistic transformation of the cumulative signal weights:

$$S_{raw} = w_{max} + \sum_{i \neq max} f(w_i)$$

Where $f(w_i)$ is a decaying accumulation factor to prevent artificial score bloating from redundant signals. The raw score is then passed through a corporate noise cap $C$ and a logistic sigmoid to map the result to the $[0, 100]$ interval.

### 2.2. Entropy & Information Theory
For binary masquerading and obfuscation detection, Sentinel utilizes Shannon Entropy ($H$):

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_b P(x_i)$$

Sentinel triggers a **Security Finding** if $H(X) > 7.5$ in source code (suggesting packing or base64 payloads) or a **Policy Violation** if $H(X) < 1.0$ in large files (suggesting low-entropy junk padding used for masquerading).

## 3. Algorithmic Complexity

### 3.1. Time Complexity
The scanning engine maintains a linear time complexity relative to the size of the repository.
- **Tree Traversal**: $O(F)$ where $F$ is the total number of files.
- **File Ingress**: $O(N)$ where $N$ is the number of bytes in the file.
- **Pattern Matching**: $O(N + M)$ using optimized regex engines, where $M$ is the number of active rules.

The total complexity of a single-pass audit is expressed as:
$$T(n) = O(\sum_{i=1}^{F} (N_i \times M))$$

In **Fast Mode**, the engine reduces $M$ by 85%, considering only critical deterministic vectors, achieving a sub-second response time for large PRs.

## 4. Adaptive Gate Orchestration

Sentinel implements a state-machine that escalates the analysis depth based on the **Git Diff Surface Area**.

| Trigger | Gate Level | SCRUTINY Depth | Exit Code |
| :--- | :--- | :--- | :--- |
| Source Change | 1 (Standard) | AST Heuristics | 1 / 0 |
| Dependency Update | 2 (Supply) | Lockfile Audit | 2 / 0 |
| Binary Artifact | 3 (Artifact) | Magic-Byte Logic | 2 / 0 |
| Manual Audit | 4 (Forensic) | Full Node_Modules | 1 / 2 / 0 |

## 5. Performance Report (v3.6.1)

| Benchmark Scenario | Avg. Latency | Memory Peak | Verdict Confidence |
| :--- | :--- | :--- | :--- |
| Single File (10KB) | 12ms | 45MB | 98% |
| PR Diff (5 files) | 45ms | 52MB | 95% |
| Full Audit (1.5K files) | 1.8s | 125MB | 92% |
| Forensic Scan (10K+ files) | 8.4s | 340MB | 88% |

## 6. Formal Exit Code Contract
Sentinel communicates with the orchestration layer (Jenkins, GitHub Actions, GitLab CI) through standard POSIX exit codes:

1. **`0` (PASS)**: Operational clearance. No security or policy flags.
2. **`1` (SECURITY)**: Active threat identified. Blocking recommended.
3. **`2` (POLICY)**: Governance violation. Manual review required.
4. **`3` (ERROR)**: Internal engine failure or corrupted metadata.
