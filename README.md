# 🛡️ Sentinel: Local Security Guardian for GitHub Repositories

**[Visit the Official Website](https://javier20dev25.github.io/Sentinel/)**

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It combines an Electron-based desktop application with a robust Node.js backend and a versatile CLI.

---

## Vision

Sentinel acts as a persistent "Overwatch" for your development environment, scanning PRs, commits, and local configurations in real-time, all while keeping your security data entirely under your control.

## 🌐 Sentinel Local Web Edition v1.0

This release marks the evolution of Sentinel into a **proactive security platform**. It introduces three major security layers designed to prevent threats before they reach your remote repositories.

### ✨ New Enterprise-Grade Features

- **🛡️ Sentinel Project Shield (SPS)**: 
  - **In-place Hardening**: Automatically configures `.npmrc` to disable scripts and enforce exact versions.
  - **AST Static Analysis**: Deep inspection of dependencies using `acorn` to detect data exfiltration and C2 communication.
  - **Safe Install**: A supervised installation flow that intercepts malicious packages in real-time.

- **🔒 Asset Guard (DLP)**:
  - **Forbidden Asset Tracker**: Mark sensitive files (SSH keys, `.env`, certificates) as "PROHIBITED".
  - **Push Interception**: Automatically blocks `git push` if any prohibited asset is detected in the staging area.
  - **Master Password Override**: Secure bypass mechanism requiring your master password for emergency pushes.

- **📜 Global Audit Trail (SGA)**:
  - **Immutable Logging**: Every detection, push, and configuration change is recorded in a local SQLite audit table.
  - **GitHub Commit Traceability**: Successful pushes automatically capture the Git commit hash, providing a direct link from Sentinel to the specific changes in GitHub.
  - **Interactive Timeline**: A premium glassmorphic interface to review all security events across all your projects.

### 🔐 Getting Started with Hardened Access

1. **Initialize Master Password**: On the first run, Sentinel will ask you to set a master password (with double confirmation). This password is encrypted using `bcrypt` and is required for unlocking the suite and for security overrides.
2. **Session Control**: Use the new sidebar controls to **Lock Sentinel** (session clear) or **Shutdown Core** (stops the backend process entirely).

---

## 🛠️ Tech Stack

- **Frontend**: [React.js](https://reactjs.org/) + [Vite](https://vitejs.dev/) + [Framer Motion](https://www.framer.com/motion/) (Premium UI)
- **Desktop Wrapper**: [Electron](https://www.electronjs.org/)
- **Backend**: [Express.js](https://expressjs.com/) (Hardened API)
- **Database**: [SQLite](https://www.sqlite.org/) (via `better-sqlite3`)
- **Git Engine**: Direct [Git](https://git-scm.com/) & [GitHub CLI](https://cli.github.com/) integration

---

## Key Features

- **Real-time Scanning**: Monitors for secrets, vulnerabilities, and misconfigurations in local paths and remote repositories.
- **Interactive Security Dashboard**: Manage all your linked repositories and security status from a sleek, glassmorphic UI.
- **Built-in CLI**: Run security audits and manage links directly from your terminal.
- **Hardened Command Execution**: Sentinel uses strict whitelisting and direct argument arrays to prevent shell injection and path traversal attacks.
- **GitHub Auth Integration**: Uses official OAuth via the GitHub CLI for secure access.

---

## 🚀 Tutorial: Running Sentinel Locally (Recommended)

The best way for developers to experience Sentinel—and contribute to its core—is to run it directly from the source. No installers, no Windows SmartScreen warnings, and 100% control over the environment.

### Prerequisites

1. [Node.js](https://nodejs.org/) (v18 or higher)
2. [Git](https://git-scm.com/) installed
3. [GitHub CLI (gh)](https://cli.github.com/) installed and authenticated (`gh auth login`)

### A Single Command to Overwatch

Open your favorite terminal (PowerShell, Bash, Command Prompt) and paste this single line:

```bash
git clone https://github.com/javier20dev25/Sentinel.git && cd Sentinel/src/ui && npm install && npm run electron:dev
```

And BOOM 💥! Electron will download, compile, and open with the full Sentinel dashboard connected to your local backend. Everything runs directly on your machine.
*(Note: The first time running this may take a minute since it compiles the native SQLite module for your system).*

---

## 📦 Alternative: Pre-built Downloads

Pre-built Windows binaries are available on the [Releases](https://github.com/javier20dev25/Sentinel/releases/latest) page if you prefer a standard setup:

| File | Description |
|---|---|
| `Sentinel Setup.exe` | Windows installer |
| `Sentinel-win32-x64.zip` | Portable -- extract and run directly |

> **Important**: Since Sentinel is independently developed and not currently enterprise code-signed, Windows SmartScreen or Smart App Control may show a warning.
> - Click **"More info"** then **"Run anyway"** to proceed.
> - If you are blocked by Smart App Control, it is highly recommended to use the **Run from Source** tutorial above.

---

## 🛡️ Security Principles

Sentinel was built with a "Security-First" approach:
- **Zero Shell Interaction**: All system commands are executed via `execFileSync` with static argument arrays, remediating Common Weakness Enumeration issues like [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- **In-Memory Sanitization**: All logs and outputs are sanitized before being displayed or stored.
- **Local Sovereignty**: No scanning data ever leaves your machine; it stays securely in your local SQLite database.

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

*Sentinel: Because your code deserves an uncompromising guardian.*
