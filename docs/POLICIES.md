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

## 4. Compliance

Sentinel is designed to assist with security compliance (e.g., SOC2, ISO 27001) by providing a local audit trail. However, Sentinel is a tool, not a certification. Users are responsible for their own security posture.
