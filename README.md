# Sentinel: Local Security Guardian for GitHub Repositories

**[Official Site](https://javier20dev25.github.io/Sentinel/) | [User Guide](docs/USER_GUIDE.md) | [CLI Reference](docs/CLI_REFERENCE.md) | [Sandbox Guide](docs/SANDBOX_GUIDE.md) | [Testing Guide](docs/TESTING_GUIDE.md) | [Architecture](docs/ARCHITECTURE.md) | [Policies](docs/POLICIES.md)**

## 🇪🇸 Resumen Ejecutivo (Spanish)
Sentinel 3.0 integra una infraestructura de **Sandbox Dinámico** basada en GitHub Actions para el análisis de comportamiento en tiempo de ejecución. Esta funcionalidad permite identificar amenazas que evaden el análisis estático, tales como la ejecución de binarios WebAssembly (WASM), conexiones de red no autorizadas a dominios de comando y control (C2), y alteraciones en la integridad de los archivos de bloqueo (lockfiles) durante el proceso de instalación.

---

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It combines an Electron-based desktop application with a robust Node.js backend and a versatile CLI.

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

* **Real-time Scanning**: Constant monitoring for secrets, vulnerabilities, and misconfigurations in local and remote paths.
* **Interactive Security Dashboard**: Manage all your linked repositories and security status from a sleek, professional interface.
* **Built-in CLI**: Run security audits, manage links, and trigger scans directly from your terminal.
* **Hardened Command Execution**: Uses strict whitelisting and direct argument arrays to prevent shell injection (CWE-78).
* **GitHub Auth Integration**: Secure OAuth flow via the official GitHub CLI for repository access.

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

## 🤖 Guide for AI Agents (CLI Automation)

If you are an AI agent, CI/CD runner, or an automator looking to use Sentinel from the terminal, Sentinel provides a robust CLI to run headless repository checks.

### Pre-Pull / Commit Analysis (`sentinel analyze --local`)
When trying to push code to a repository, first run:
```bash
sentinel analyze --local
```
**Blockers:**
- If Critical Threats (riskLevel >= 8) are found, the CLI will block with `exit code 1`.
- If the agent inadvertently modified a **Protected File** (e.g. personal documents or local `.env` files marked by the user via the UI), the CLI will also throw an error and halt execution to prevent a data leak.

**How to resolve Protected File Blocks:**
As an AI Agent, if you encounter a Protected File violation, you must respect the user's local security. Use the provided flags to bypass cleanly:
- `--exclude-protected`: Sentinel will automatically execute `git reset HEAD <file>` on the protected files, unstaging them safely, and allowing the rest of the commit to proceed without the leak.
- `--force`: DANGEROUS. Only use this if you have explicit user permission. It bypasses the Protected File check completely.

Example usage:
```bash
# Recommended for AI Agents:
sentinel analyze --local --exclude-protected
```

---

## 🤝 Calling All Developers & White Hats!

Sentinel is a community-driven project built to secure the open-source ecosystem. **We need YOUR help to make it better!**

Whether you are a React wizard, a Node.js backend architect, or an active security researcher writing better threat signatures, **this tool is yours to improve**. 

### How to contribute:
1. Clone the project using the tutorial above.
2. Look through our issues or create one for a feature you'd like to see.
3. Hack away! Break things, build new panels, add better regex security scanners!
4. Submit a **Pull Request**. Every contributor is honored.

---

## ⚖️ License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full text.

### 📜 Credits, Ethics & Attribution (Required by Author)

While the legal license is MIT, the author (javier20dev25) requests that all users and developers adhere to the following **mandatory** conditions for the health of the project and its community:

1.  **Prior Notification**: If you intend to deploy Sentinel or a derivative work (commercial or non-commercial) in a production or public environment, you **must contact the author first** for awareness and potential collaboration.
2.  **Legitimate & Good Use Only**: Sentinel is a tool for defense. It must only be used for legitimate security engineering, auditing, and defensive research. Any malicious use is strictly prohibited by our code of conduct.
3.  **Mandatory Attribution**: Any product or service built using Sentinel's code must clearly display a link to this repository and satisfy the "Powered by Sentinel" attribution in a visible part of the product's interface or website.

---

*Sentinel: Because your code deserves an uncompromising guardian.*
