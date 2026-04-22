# Sentinel Governance & Policy Framework (v3.0)

Este documento establece las normas de privacidad, uso y colaboración de Sentinel.

> [!NOTE]
> **Resumen Ejecutivo (Español)**:
> Sentinel se rige por una política de **Cero Telemetría**: ningún dato sale de tu máquina. El uso de la herramienta debe ser ético y personal. Fomentamos las colaboraciones externas y las mejoras a través de Pull Requests, siempre bajo una revisión técnica rigurosa para mantener la integridad de la suite.

---

## 1. Data Sovereignty & Privacy Policy

Sentinel is built on the principle of **Local-First Security**.

### Zero Telemetry Commitment
- **No Data Collection**: Sentinel does NOT collect, store, or transmit any telemetry data, usage statistics, or user behavior patterns.
- **Offline Scanning**: All static code analysis is performed entirely offline. 
- **Local Storage**: Your repository metadata, scan logs, and threat intelligence remain exclusively in your local SQLite database (`sentinel.db`).
- **Transparency**: Every outgoing request (e.g., to GitHub API) is strictly for orchestration and user-inititiated actions (like fetching PR info or triggering workflows).

---

## 2. Responsible Use Policy

As a powerful security tool, Sentinel should be used ethically:
- **Authorized Audit Only**: Use Sentinel primarily on repositories you own or have explicit permission to audit.
- **Dynamic Sandbox Safety**: The GitHub Actions sandbox is designed for behavioral analysis. Do not use it to intentionally compromise GitHub's infrastructure or evade their Terms of Service.
- **Malware Research**: When auditing malicious packages (e.g., Axios 2026), ensure the environment is correctly isolated as described in the [Sandbox Guide](SANDBOX_GUIDE.md).

---

## 3. Collaboration & Improvement Policy

Sentinel is a community-driven project. We welcome improvements and external collaborations.

### Acceptance of Improvements
We actively seek contributions in the following areas:
- **New Detection Rules**: Adding new YAML-based signatures for emerging threats.
- **CLI/UI Enhancements**: Improving the developer experience and visual aesthetics.
- **Bug Fixes**: Security remediation is our top priority.

### How to Collaborate
1.  **Fork & Branch**: Create a feature branch for your improvements.
2.  **Standards**: Follow the coding style found in `src/ui/backend/lib/sanitizer.js` (strict input validation).
3.  **Review Process**: Every Pull Request undergoes a technical peer review focusing on:
    *   Security integrity (no injection vulnerabilities).
    *   Performance (no blocking the UI main thread).
    *   Testing coverage (must include unit tests in `tests/`).

---

## 4. Licensing & Commercial Redistribution

Sentinel operates under a balanced intellectual property model designed to support the developer community while protecting commercial value.

### Business Source License 1.1
- **Individual/Dev Use**: Sentinel is free to use, modify, and distribute for non-production development, research, and open-source community contributions.
- **Enterprise Internal Use**: Use within internal company pipelines is permitted for security auditing purposes.
- **Commercial Restriction**: The redistribution of Sentinel as part of a paid product, the provisioning of Sentinel as a managed service (SaaS), or its use in revenue-generating commercial audits is prohibited without an explicit commercial license.

### Commercial Licensing Contact
Organizations wishing to integrate Sentinel into their commercial offerings or supply chain platforms must formalize a license agreement. Contact the Licensor at the official project repository for terms.

---

## 5. Release Governance & Operational Benchmarking

Sentinel enforces technical governance during the research and development lifecycle:

### Operational Benchmarking
Any alteration to the detection engine is measured against a strict local Benchmark Suite. A release candidate or contribution is only considered valid if:
- It achieves a 0% False Positive rate on clean tooling files.
- It maintains 100% True Positive recall on known adversarial evasion vectors.

### Governance Audit Standards
All detection rules must be traceable. This means every diagnostic output must include:
- A standardized `rule_id` under the `SARB-` namespace.
- A human-readable `explanation` of the detection logic.
- The `rulepack_version` identifier representing the active security baseline.

---

## 6. Developer Security Hygiene & Branch Protection

Sentinel is most effective when integrated into a hardened repository environment. We recommend the following practices for all developers and organizations using this engine.

### Mandatory Branch Protection
- **Protect Main/Master**: Never allow direct pushes to the primary branch. All changes must go through a Pull Request.
- **Required Reviews**: Enable at least one mandatory code review before merging.
- **Status Checks**: Ensure that `sentinel scan --ci` is a required status check for every PR.

### Native GitHub Security Tools
We recommend enabling the following features in your repository settings:
- **Dependency Graph & Dependabot**: Automated auditing and updates for outdated or vulnerable packages.
- **Secret Scanning**: Scans for accidental exposure of credentials, tokens, and keys.
- **CodeQL Analysis**: Static analysis for common software vulnerabilities.

### Identity & Access
- **Multi-Factor Authentication (MFA)**: All contributors must have MFA enabled on their accounts.
- **SSH/GPG Signing**: We encourage signing commits to ensure provenance and prevent identity spoofing.

---
