# Sentinel Security Engine

Sentinel is a **Supply Chain Enforcement Layer** for modern development. It intercepts package installations across ecosystems, classifies trust via multi-factor reputation scoring, and enforces organizational security policy before any code touches your infrastructure.

**Version 3.8.0 — Universal Trust Engine**

---

## 🛡️ What Sentinel Does

Sentinel is not a vulnerability scanner. It's a **Dependency Installation Firewall**.

- It decides **if something enters**, not what's wrong with it.
- It detects **behavioral malice** (typosquatting, lifecycle scripts, image mimicry), not public CVEs.
- It **redacts intelligence** from unauthorized users to prevent weaponization.

```
Developer runs: npm install axois
                     │
              Sentinel Guard intercepts
                     │
              ┌──────┴──────┐
              │ Trust Cache  │ ← instant if seen before
              └──────┬──────┘
                     │ miss
              ┌──────┴──────┐
              │  Adapter     │ ← npm / pip / docker
              │  Analysis    │
              └──────┬──────┘
                     │
              ┌──────┴──────┐
              │ Policy       │ ← strict (CI) / advisory (local)
              │ Engine       │
              └──────┬──────┘
                     │
              ⛔ BLOCK  or  ✓ PROCEED
```

## 🌐 Ecosystem Coverage

| Adapter | Managers | Threat Model |
|---|---|---|
| **npm** | npm, yarn, pnpm | Typosquatting, scope camouflage, lifecycle scripts |
| **pip** | pip, pip3, poetry, uv | Typosquatting, entry_point abuse, PEP-503 confusion |
| **docker** | docker pull | Publisher tier, image mimicry, `:latest` blocking, digest enforcement |

Adding a new ecosystem = one adapter file. Core scoring, cache, and policy remain untouched.

## 🚀 Quickstart

```bash
# Secure installation (any ecosystem)
sentinel install npm lodash
sentinel install pip requests
sentinel install docker nginx@sha256:abc123

# Enable OS-level interception (every npm/pip/docker goes through Sentinel)
sentinel guard enable

# Manage trust
sentinel trust add react --adapter npm
sentinel trust block malicious-pkg --adapter pip
sentinel trust list

# Advisory mode (warn, never block — for local dev)
sentinel install npm unknown-pkg --advisory

# Repository security scan
sentinel scan .
```

## ⚖️ Enforcement Modes

| Mode | When | Behavior |
|---|---|---|
| **Strict** | CI/CD (auto-detected) | Hard blocks. `exit 1` on BLOCK verdict |
| **Advisory** | Local dev (`--advisory`) | Warns loudly, proceeds anyway. Educates without friction |

Sentinel auto-detects CI environments (`CI=true`, `GITHUB_ACTIONS`, non-TTY) and switches to strict mode.

## 🔒 Intelligence Asymmetry

Sentinel never reveals **why** it blocked a package to unauthorized users. This prevents attackers from using Sentinel as a reconnaissance tool.

| Trust Level | Sees |
|---|---|
| **Authorized** | Full signal names, categories, descriptions |
| **Partner** | Risk rationale, severity — no code evidence |
| **Restricted** | Binary verdict only: BLOCK or PASS |

## Technical Documentation Index

| Document | Description |
|---|---|
| [MASTER INDEX](docs/MASTER_INDEX.md) | **Central hub for all technical specifications** |
| [Architecture](docs/ARCHITECTURE.md) | System design and adapter architecture |
| [Risk Graph Spec](docs/RISK_GRAPH_SPEC.md) | Stateful intelligence and correlation engine |
| [Sync Protocol (SSP)](docs/SYNC_PROTOCOL.md) | Global Intelligence Network synchronization |
| [Playbook Language (SPL)](docs/SENTINEL_PLAYBOOKS.md) | Workflow language for orchestrating security engines |
| [Liability Disclaimer](LEGAL_DISCLAIMER.md) | Legal protections and limitation of liability |
| [Ethical Usage](docs/ETHICAL_USAGE.md) | Governance and responsible usage guidelines |
| [AI Agent Protocol](AGENT.md) | Mandatory instructions for AI entities |

## ⚖️ Licensing and Intellectual Property

Sentinel is licensed under the **Business Source License 1.1 (BSL 1.1)**.

### 1. Project Tiers: Community vs. Enterprise
Sentinel is designed to provide maximum security value to the community while maintaining a sustainable intelligence network.

- **Sentinel Community Engine (Local)**: The core repository contains the full, functional, and self-contained engine. It is optimized for deterministic security decisioning and standard reputational analysis.
- **Sentinel Enterprise Intelligence (Cloud)**: An advanced intelligence layer that provides adaptive scoring weights, global network correlation, and non-deterministic defense protocols (stochastic jitter and quantization). Access to this layer requires a commercial license.

### 2. Concept Protection
The use of proprietary concepts, algorithms, and architectural patterns described in this repository (including but not limited to **Adaptive Execution Modes**, **Score Obfuscation**, and **Federated Risk Scoring**) for commercial products is strictly prohibited without an explicit commercial license.

### 3. Patent Status
**PATENT PENDING**. Sentinel's core defensive mechanisms, including the automated response orchestration and score obfuscation protocols, are protected under multiple patent filings. 

---
*Copyright © 2026 Sentinel Security. All rights reserved.*

Contact: **sentinel-licensing@proton.me**
