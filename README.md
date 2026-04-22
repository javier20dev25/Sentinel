# Sentinel Security Engine

Sentinel is an enterprise-grade, auditable security decision engine for CI/CD pipelines. It identifies high-side offensive operations, supply chain anomalies, and binary masquerading before code is merged.

## The Problem: Decision Latency in the AI Era
Artificial Intelligence is drastically accelerating code generation. As we transition into a future where most code is AI-assisted, the security bottleneck is no longer **generating** code, but **deciding what to accept** into your production pipeline.

Relying on AI agents to audit AI-generated code introduces new frictions:
- **Scaling Costs**: Reviewing every PR with LLM-based agents causes token consumption and operational costs to grow exponentially with code volume.
- **Non-Determinism**: AI-based security audits can be inconsistent, occasionally missing sophisticated evasion techniques or producing hallucinations.
- **Pipeline Latency**: Critical CI/CD workflows require low-latency, deterministic verdicts that large models cannot always provide.

## The Sentinel Philosophy: Deterministic Verification
Sentinel does not try to be "intelligent" in the way an LLM is; it is a **Deterministic Decision Layer**. 

While developers may feel safe using AI for 99% of their workflow, the risk of malicious code injection—whether through subtle prompt injection or compromised transitive dependencies—is at an all-time high. Sentinel acts as a high-fidelity gatekeeper that identifies malicious intent fingerprints (SARB) and policy violations with mathematical precision, without the overhead or unpredictability of agentic AI auditors. 

**It is the predictable "NO" gate for an unpredictable era.**

## Core Capabilities
- **Adaptive Security Gates**: Context-aware escalation from Fast PR checks to deep Forensic audits.
- **Intent Fingerprinting**: Mathematical scoring of source code signals through the SARB engine.
- **Semantic Governance**: Differentiates between Security Threats (Exit 1) and Policy Violations (Exit 2).
- **Supply Chain Integrity**: Real-time analysis of lockfiles, transitive registries, and lifecycle scripts.

## Installation
```bash
npm install -g sentinel-security-engine
```

## Quickstart (60 Seconds)

### 1. Perform a fast scan on a Pull Request
```bash
sentinel scan . --fast --ci
```

### 2. Deep Audit a local directory
```bash
sentinel audit . --forensic
```

### 3. Explain the logic behind a finding
```bash
sentinel explain path/to/flagged_file.js
```

### 4. Install Git Security Hooks
```bash
sentinel hook-install
```

## CI/CD Exit Code Contract
Sentinel communicates with your pipeline using standard POSIX exit codes:
- `0`: PASS. Safe to proceed.
- `1`: SECURITY. Active threat detected. Block build.
- `2`: POLICY. Governance violation. Manual review required.
- `3`: ERROR. Internal engine failure.

## Documentation
- [Technical Specification](docs/TECHNICAL_SPECIFICATION.md): Formal algorithmic analysis and complexity.
- [Security Gates](docs/SECURITY_GATES.md): Decision logic and escalation triggers.
- [Changelog](CHANGELOG.md): Historical versioning and evolution.

## Licensing

### Community & Development
Sentinel is licensed under the **Business Source License 1.1 (BSL 1.1)**.
- **Permitted**: Non-commercial use, research, internal development, and community contributions.
- **Conversion**: This license automatically converts to **MIT** on **April 22, 2029**.

### Commercial Licensing
Usage of Sentinel for commercial redistribution, integration into paid products, or as a hosted service (SaaS) is strictly prohibited under the BSL 1.1 without an explicit commercial agreement.

If you plan to:
- Integrate Sentinel into a commercial security platform.
- Offer Sentinel as a managed service.
- Use Sentinel for revenue-generating security audits.

Please contact the author for commercial licensing terms.
