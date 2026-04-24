# Sentinel: Formal Technical Specification

## 1. Abstract
Sentinel is an auditable security decision engine designed for high-velocity CI/CD environments. It implements a multi-layered static analysis heuristic model that classifies source code anomalies into semantic risks (Security Findings vs. Policy Violations). This document details the algorithmic complexity, mathematical foundations of entropy analysis, and the adaptive gate orchestration logic.

## 2. Theoretical Framework

### 2.1. Probabilistic Risk Aggregation
Unlike additive scoring models, Sentinel's core engine aggregates risk using a **Probabilistic Composition Matrix**. Each finding $i$ contributes a normalized base risk $r_i \in [0, 1]$. To prevent score saturation from redundant signals, the aggregated risk $R$ is calculated as the probability of compromise:

$$R = 1 - \prod_{i=1}^{n} (1 - (r_i \times w_i))$$

Where $w_i$ is contextual weight (e.g., $w=1.2$ for findings in `package.json`, $w=0.8$ for obfuscation in `.test.js`). 

### 2.2. Quantization and Stable Jitter (Oracle Mode)
To prevent side-channel inversion (Oracle Attacks), Sentinel obscures the raw probabilistic risk $R_c$ for unauthorized observers. The score is mapped to discrete buckets $B = \{0.0, 0.25, 0.50, 0.75, 1.0\}$, and obscured with Stable Jitter ($\epsilon$):

$$R_r = \text{clamp}(\text{nearest}(R_c, B) + \epsilon, 0, 1)$$

$$\epsilon = \text{Hash}(F \cdot U \cdot T) \pmod{0.06} - 0.03$$

This yields an $\epsilon$ bound strictly between $\pm 0.03$, ensuring mathematical reproducibility within a session window ($T$) while remaining non-invertible across sessions.

### 2.3. Entropy & Information Theory
For binary masquerading and obfuscation detection, Sentinel utilizes Shannon Entropy ($H$):

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_b P(x_i)$$

Sentinel triggers a **Security Finding** if $H(X) > 7.5$ in source code (suggesting packing or base64 payloads) or a **Policy Violation** if $H(X) < 1.0$ in large files (suggesting low-entropy junk padding used for masquerading).

### 2.4. Input Sanitization & Signal Integrity (v3.7.1)
Sentinel implements a three-stage sanitization pipeline to guarantee signal quality:
1. **Path Guard**: `resolvedPath.startsWith(rootPath)` logic to prevent recursive directory traversal and symlink-based exfiltration.
2. **Binary Sampling**: High-efficiency first 512-byte inspection to classify files and skip non-text assets without full I/O saturation.
3. **Incremental Cache**: Fast metadata-tracking (path/size/mtime) to avoid redundant analysis of unchanged files.

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
| Full Audit (1.5K files) | 2.1s | 145MB | 94% |
| Forensic Scan (10K+ files) | 9.2s | 410MB | 90% |

## 6. Formal Exit Code Contract
Sentinel communicates with the orchestration layer (Jenkins, GitHub Actions, GitLab CI) through standard POSIX exit codes:

1. **`0` (PASS)**: Operational clearance. No security or policy flags.
2. **`1` (SECURITY)**: Active threat identified. Blocking recommended.
3. **`2` (POLICY)**: Governance violation. Manual review required.
4. **`3` (ERROR)**: Internal engine failure or corrupted metadata.
