# 🛡️ Sentinel: Local Security Guardian for GitHub Repositories

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It combines an Electron-based desktop application with a robust Node.js backend and a versatile CLI.

---

## 🚀 Vision

Sentinel acts as a persistent "Overwatch" for your development environment, scanning PRs, commits, and local configurations in real-time, all while keeping your security data entirely under your control.

## 🛠️ Tech Stack

- **Frontend**: [React.js](https://reactjs.org/) + [Vite](https://vitejs.dev/) + [TailwindCSS](https://tailwindcss.com/)
- **Desktop Wrapper**: [Electron](https://www.electronjs.org/)
- **Backend**: [Express.js](https://expressjs.com/) (Hardened API)
- **Database**: [SQLite](https://www.sqlite.org/) (via `better-sqlite3`)
- **CLI**: [Commander.js](https://github.com/tj/commander.js)
- **GitHub Integration**: Official [GitHub CLI (gh)](https://cli.github.com/) bridge

## ✨ Key Features

- **Real-time Scanning**: Monitors for secrets, vulnerabilities, and misconfigurations in local paths and remote repositories.
- **Interactive Security Dashboard**: Manage all your linked repositories and security status from a sleek, glassmorphic UI.
- **Built-in CLI**: Run security audits and manage links directly from your terminal.
- **Hardened Command Execution**: Sentinel uses strict whitelisting and direct argument arrays to prevent shell injection and path traversal attacks.
- **GitHub Auth Integration**: Uses official OAuth via the GitHub CLI for secure access.

## 📦 Installation & Setup

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [GitHub CLI (gh)](https://cli.github.com/) installed and authenticated (`gh auth login`)
- [Git](https://git-scm.com/) installed

### Local Development

1. **Clone the project** (this repo).
2. **Install dependencies**:
   ```bash
   npm install
   cd src/ui && npm install
   ```
3. **Launch the Developer Suite** (Vite + Electron):
   ```bash
   cd src/ui
   npm run electron:dev
   ```

## 🔐 Security Principles

Sentinel was built with a "Security-First" approach:
- **Zero Shell Interaction**: All system commands are executed via `execFileSync` with static argument arrays, remediating Common Weakness Enumeration issues like [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- **In-Memory Sanitization**: All logs and outputs are sanitized before being displayed or stored.
- **Local Sovereignty**: No scanning data ever leaves your machine; it stays in your local SQLite database.

## 🤝 Contribution

Managed and maintained by [javier20dev25](https://github.com/javier20dev25).

---

*Sentinel: Because your code deserves an uncompromising guardian.*
