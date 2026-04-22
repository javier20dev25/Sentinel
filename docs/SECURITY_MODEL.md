# Security Model & Limitations

This document defines the operational boundaries, detection philosophy, and ethical framework of the Sentinel Security Engine. Understanding these factors is critical for the correct interpretation of Sentinel's security signals.

## 1. Security Model

Sentinel operates as a heuristic and structural decision engine. Unlike traditional signature-based scanners, it focuses on identifying offensive patterns and intentions.

### 1.1 The SARB Engine
The engine utilizes the **Security Analysis and Response Baseline (SARB)** to evaluate code. Every diagnostic is derived from:
- **Structural Analysis**: Static inspection of the Abstract Syntax Tree (AST) to identify dangerous primitives and unreachable code paths used for evasion.
- **Intent Fingerprinting**: Matching specific sequences of operations (scenarios) that indicate high-confidence offensive behavior (e.g., Decryption -> Network Access -> Execution).
- **Confidence Scoring**: A mathematical model that aggregates signals into an auditable final score (0-100), avoiding binary "all or nothing" detections.

### 1.2 Multi-Tier Scanning
- **Fast Mode**: A high-velocity subset of rules (Severity >= 8) designed for instantaneous feedback (<1s) during development cycles.
- **Deep Analysis**: A comprehensive scan including full dependency graphs and administrative configuration audits.
- **Sandbox Execution**: (Optional) Dynamic analysis that executes code in an isolated environment to capture runtime payloads.

## 2. Limitations

Sentinel is high-fidelity, but it is not a "silver bullet." Users must be aware of the following technical boundaries:

### 2.1 The 100% Fallacy
No security tool can provide 100% protection. Detection is probabilistic. Sophisticated, state-sponsored actors or previously unknown (Zero-Day) exploits may evade heuristic patterns. Sentinel reduces the attack surface but does not eliminate it entirely.

### 2.2 Technological Scope
The engine is optimized for modern web ecosystems and high-level languages:
- **Primary Support**: JavaScript/Node.js, Python, Go, Rust.
- **Workflow Auditing**: GitHub Actions and CI/CD manifests.
Sentinel is not currently designed to audit low-level systems (C/C++ firmware), legacy mainframe architectures, or proprietary compiled binaries outside its specific rule-packs.

### 2.3 Advanced Evasion
While Sentinel detects many obfuscation and environment-evasion techniques, extremely creative or customized evasion methods may still succeed. We recommend Sentinel as a layer of a multi-defense strategy, never as the sole security control.

## 3. Ethical Use

Sentinel is a defensive technology designed for security posture management and governance.

- **Defensive Nature Only**: Sentinel is developed to protect repositories, developers, and organizations. It is not an offensive tool, nor is it intended to be used for the development or testing of malicious software.
- **Operational Discipline**: We do not engage in "challenges" or confrontations with malicious actors. Our goal is to provide reliable, auditable evidence for security teams to make informed decisions.
- **Transparency**: Every finding is backed by a SARSB-ID and an explanation, ensuring that security decisions are defendable and transparent.
