# Sentinel: Local Security Guardian for GitHub Repositories

**[Visit the Official Website](https://javier20dev25.github.io/Sentinel/)**

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It combines an Electron-based desktop application with a robust Node.js backend and a versatile CLI.

---

## Vision

Sentinel acts as a persistent "Overwatch" for your development environment, scanning PRs, commits, and local configurations in real-time, all while keeping your security data entirely under your control.

## Tech Stack

- **Frontend**: [React.js](https://reactjs.org/) + [Vite](https://vitejs.dev/) + [TailwindCSS](https://tailwindcss.com/)
- **Desktop Wrapper**: [Electron](https://www.electronjs.org/)
- **Backend**: [Express.js](https://expressjs.com/) (Hardened API)
- **Database**: [SQLite](https://www.sqlite.org/) (via `better-sqlite3`)
- **CLI**: [Commander.js](https://github.com/tj/commander.js)
- **GitHub Integration**: Official [GitHub CLI (gh)](https://cli.github.com/) bridge

## Key Features

- **Real-time Scanning**: Monitors for secrets, vulnerabilities, and misconfigurations in local paths and remote repositories.
- **Interactive Security Dashboard**: Manage all your linked repositories and security status from a sleek, glassmorphic UI.
- **Built-in CLI**: Run security audits and manage links directly from your terminal.
- **Hardened Command Execution**: Sentinel uses strict whitelisting and direct argument arrays to prevent shell injection and path traversal attacks.
- **GitHub Auth Integration**: Uses official OAuth via the GitHub CLI for secure access.

---

## Quick Start (Recommended)

The recommended way to run Sentinel is directly from source. No installer, no SmartScreen warnings, no compatibility issues.

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [GitHub CLI (gh)](https://cli.github.com/) installed and authenticated (`gh auth login`)
- [Git](https://git-scm.com/) installed

### Run in 4 commands

```bash
git clone https://github.com/javier20dev25/Sentinel.git
cd Sentinel/src/ui
npm install
npm run electron:dev
```

That's it. Electron opens with the full Sentinel dashboard connected to your local backend. Everything runs on your machine.

> **Note**: The first `npm install` may take a minute since it compiles the native SQLite module for your system. This only happens once.

---

## Alternative: Pre-built Downloads

Pre-built Windows binaries are available on the [Releases](https://github.com/javier20dev25/Sentinel/releases/latest) page:

| File | Description |
|---|---|
| `Sentinel Setup.exe` | Windows installer |
| `Sentinel-win32-x64.zip` | Portable -- extract and run directly |

> **Important**: Since Sentinel is not code-signed, Windows SmartScreen may show a warning.
> Click **"More info"** then **"Run anyway"** to proceed.
> If Smart App Control blocks the installer, use the portable `.zip` version or run from source (recommended above).

---

## Security Principles

Sentinel was built with a "Security-First" approach:
- **Zero Shell Interaction**: All system commands are executed via `execFileSync` with static argument arrays, remediating Common Weakness Enumeration issues like [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- **In-Memory Sanitization**: All logs and outputs are sanitized before being displayed or stored.
- **Local Sovereignty**: No scanning data ever leaves your machine; it stays in your local SQLite database.

## Contribution

Managed and maintained by [javier20dev25](https://github.com/javier20dev25).

---

*Sentinel: Because your code deserves an uncompromising guardian.*
