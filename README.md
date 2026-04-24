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

## 📄 Documentation

| Document | Description |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | System design and adapter architecture |
| [Supply Chain Firewall](docs/SUPPLY_CHAIN_GUIDE.md) | Installation firewall & Docker Zero Trust guide |
| [AI Agent Protocol](AGENT.md) | **Mandatory prompt** for AI agents working in this repo |
| [Classified Data](docs/CLASSIFIED_DATA_GUIDE.md) | Protocol for protected files and declassification |
| [Policy Governance](docs/POLICIES.md) | GaC manual and exposure levels |

## ⚖️ Licensing

Sentinel is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Free**: Personal use, internal use, research, community contribution.
- **Commercial license required**: Managed services, redistribution, competitive integration.
- **Conversion**: Automatically converts to **MIT** on April 22, 2029.

Contact: **sentinel-licensing@proton.me**
