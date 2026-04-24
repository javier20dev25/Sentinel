# Technical Specification: Sentinel Adversarial Lab (SAL) (v1.0)

## 1. Executive Summary
The Sentinel Adversarial Lab (SAL) is a continuous security verification and optimization framework. It implements a closed-loop system where an automated Attacker Engine generates mutated malicious payloads to challenge the Sentinel Security Decision Engine. The objective is to quantify detection latency, evasion resistance, and resource efficiency to drive the evolution of the Sentinel Enterprise Intelligence layer.

## 2. System Architecture

### 2.1 Attacker Engine (`attacker.js`)
Responsible for generating adversarial samples using:
- **Base Payloads**: Known malicious patterns (Typosquatting, Dependency Poisoning).
- **Mutation Vectors**: Code-level transformations (variable obfuscation, string fragmentation, dead code injection) designed to bypass static heuristics.

### 2.2 Metrics Profiler (`profiler.js`)
Captures high-resolution performance metrics during each analysis cycle:
- **Detection Latency**: Time from ingestion to final verdict.
- **Memory Pressure**: Heap delta used by the engine during complex AST inspection.
- **CPU Cycle Count**: (Planned) Quantitative measure of computational cost.

### 2.3 Lab Orchestrator (`orchestrator.js`)
The control plane that executes the "VS" loop. It maintains a historical record of all simulations, enabling:
- **Regression Detection**: Ensuring that new engine updates do not degrade detection accuracy.
- **Gaps Identification**: Locating specific mutation types that consistently evade detection.

## 3. Evolutionary Training Dynamics

### 3.1 Progressive Difficulty Scaling
SAL implements a 4-level difficulty curriculum based on performance:
- **Level 1 (Baseline)**: Low mutation intensity (0.2). Focuses on signature-based detection.
- **Level 2 (Evasive)**: Moderate intensity (0.5). Introduces basic string fragmentation.
- **Level 3 (Advanced)**: High intensity (0.8). Combines multiple obfuscation vectors.
- **Level 4 (Adversarial)**: Maximum intensity (1.0). Full mutation depth.

**Scaling Rules**:
- **3 Consecutive Wins**: Level Up.
- **2 Consecutive Losses**: Level Down/Stay.

### 3.2 Hint & Recursive Analysis Protocol
If Sentinel fails to detect a payload, the Attacker reveals the mutation vector (the "Hint"). The Orchestrator then re-executes the analysis in **Boosted Mode** (lowered risk thresholds) to verify if the signal is present but silenced. This provides data for threshold optimization.

## 4. Security Isolation Guidelines (Mandatory)
To protect the host infrastructure during high-intensity simulations, SAL must be executed under the following conditions:
- **Air-Gapped Environment**: No external network access unless specifically required for telemetry.
- **Containerization**: Use of ephemeral Docker containers or disposable VMs.
- **Resource Constraints**: Strict CPU and RAM limits enforced via CGroups to prevent denial-of-service during complex AST analysis.

## 5. Persistence and Analytics
All session data is persisted in `src/ui/backend/lab/adversarial_results.json`. This acts as the project's **Continuous Intelligence Ledger**, tracking the engine's evolution over time.

---
**CONFIDENTIAL: INTERNAL GOVERNANCE ONLY**
*Copyright © 2026 Sentinel Security. All rights reserved.*
