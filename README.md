# Sentinel: Local Security Guardian for GitHub Repositories

**[Visit the Official Website](https://javier20dev25.github.io/Sentinel/)**

Sentinel is a high-performance, local security monitoring and auditing suite designed to protect your GitHub repositories from vulnerabilities, secrets leakage, and unauthorized changes. It combines an Electron-based desktop application with a robust Node.js backend and a versatile CLI.

---

## Important Notice: Active Development

Sentinel is currently a work in progress, developed by a single individual. As such, there are still bugs to resolve and features to be implemented across all interfaces (CLI, Desktop App, and Web Version). We appreciate your patience as we continue to refine the security engine and user experience.

---

## Available Versions

Sentinel is distributed in three distinct formats to suit different user needs.

### 1. Windows Installer (Standard Edition)
The easiest way to get started on Windows.
- **Format**: .exe installer.
- **Installation**: Download `Sentinel Setup.exe` from the Releases page, run it, and follow the installation wizard.
- **Note**: Since the application is not yet enterprise code-signed, you may see a Windows SmartScreen warning. Click "More info" and "Run anyway" to proceed.

### 2. Portable Version (No Installation)
For users who prefer not to install software or want to run Sentinel from a USB drive.
- **Format**: .zip archive.
- **Usage**: Download `Sentinel-win32-x64.zip`, extract the contents to a folder, and run `Sentinel.exe` directly.

### 3. Sentinel Local Web Edition (Advanced/Power User)
This is the most powerful and feature-complete version of Sentinel. It runs directly from the source code, providing the full range of proactive security tools and direct control over the local backend server.
- **Format**: Source code execution via NPM.
- **Exclusive Features**:
  - **Sentinel Project Shield (SPS)**: Real-time environment hardening and AST-based static analysis.
  - **Asset Guard (SAG)**: Git push interception for prohibited files with master password override.
  - **Global Audit Trail (SGA)**: Full event logging with Git commit traceability and historical timeline.
  - **Direct Server Control**: Ability to remote shutdown the backend and monitor real-time system telemetry.

---

## Guide for Local Web Edition (Recommended)

Running from source provides 100% control over the security environment and bypasses all OS-level signature warnings.

### Prerequisites

1. Node.js (v18 or higher)
2. Git installed
3. GitHub CLI (gh) installed and authenticated (`gh auth login`)

### Running the Local Web Edition

Open your terminal and execute the following:

```bash
git clone https://github.com/javier20dev25/Sentinel.git
cd Sentinel/src/ui
npm install
npm run electron:dev
```

The first execution will compile the native SQLite modules for your specific system. Once running, you will be prompted to set a master password for hardened session access.

---

## Technical Features

- **Real-time Scanning**: Monitors for secrets, vulnerabilities, and misconfigurations.
- **Interactive Security Dashboard**: Glassmorphic UI for managing linked repositories.
- **Built-in CLI**: Manage links and run audits directly from the terminal.
- **Hardened Command Execution**: Uses strict whitelisting and direct argument arrays to prevent shell injection (CWE-78).
- **GitHub Auth Integration**: Secure OAuth via the official GitHub CLI.

---

## Security Principles

Sentinel follows a "Local-First" security model:
- **Zero Shell Interaction**: All commands are executed with static argument arrays.
- **In-Memory Sanitization**: Data is cleaned before storage or display.
- **Data Sovereignty**: Your security data never leaves your machine; it remains in your local SQLite database.

---

## Contributing

As this is a solo-developer project, contributions from the community are highly encouraged. Whether you specialize in React, Node.js, or Security Research, your help is valuable.

### How to contribute:
1. Clone the project using the Local Web Edition guide.
2. Review current issues or suggest new features.
3. Submit a Pull Request with your improvements.

---

*Sentinel: Protecting your code with a local, uncompromising guardian.*
