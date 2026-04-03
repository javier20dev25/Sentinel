# Sentinel: Local Security Guardian for GitHub Repositories

**[Visit the Official Website](https://javier20dev25.github.io/Sentinel/)**

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
npm run electron:dev
```
*(Note: Initial run may take a moment to compile native SQLite modules).*

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

## Contributing

As a solo-developer project, Sentinel thrives on community feedback. If you are a developer or security researcher, your contributions are highly welcome.

**How to contribute:**
1. Clone the repository using the Local Web Edition guide.
2. Review the issues or suggest new features.
3. Submit a Pull Request. Every contribution helps make Sentinel more effective.

---

*Sentinel: Because your code deserves an uncompromising guardian.*
