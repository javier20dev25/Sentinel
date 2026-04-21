# Sentinel: Local Security Guardian for GitHub Repositories

**[Official Site](https://javier20dev25.github.io/Sentinel/) | [User Guide](docs/USER_GUIDE.md) | [CLI Reference](docs/CLI_REFERENCE.md) | [AI Agent Guide](docs/AI_AGENT_ONBOARDING.md) | [Agent Interop Report](docs/AGENT_INTEROP_REPORT.md) | [Sandbox Guide](docs/SANDBOX_GUIDE.md) | [Testing Guide](docs/TESTING_GUIDE.md) | [Scan Results](docs/SCAN_TEST_RESULTS.md) | [Architecture](docs/ARCHITECTURE.md) | [Methodology](docs/METHODOLOGY.md) | [Detection Spec](docs/DETECTION_SPEC.md) | [Threat Model](docs/THREAT_MODEL.md) | [Policies](docs/POLICIES.md)**

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

Sentinel is designed to be **"Agentic-Ready"**, allowing AI agents and automation scripts to consume its security audits programmatically via structured JSON.

### Standardized JSON Response
When using the `--json` flag, Sentinel always returns a consistent object structure to ensure reliable parsing:
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

### 🏆 Essential Commands for Agents
| Command | Purpose | JSON Output Tip |
| :--- | :--- | :--- |
| `sentinel prepush --json` | **Crucial:** Analyze commits before pushing | Check `data.safe` (boolean) |
| `sentinel heal --leaks` | Automatically unstage protected files | `success: true` means fixed |
| `sentinel heal --threats` | Quarantine detected threats | `success: true` means fixed |
| `sentinel list --json` | Get all linked repositories | Returns array of repos |
| `sentinel status --json` | Get high-level security state | Check `status` field |

### ⚡ Lite Model Protocol (Gemini Flash Lite / GPT-3.5)
If you are a basic AI model, follow this simple 3-step loop to ensure a safe push:
1.  **Check**: Run `sentinel prepush --json`.
2.  **Fix**: If `data.safe` is `false`, run `sentinel heal --leaks` and/or `sentinel heal --threats`.
3.  **Verify**: Run `sentinel prepush --json` again. If `true`, proceed with `git push`.

### Advisory & Smart-Blocking Git Hooks
AI Agents should install the Sentinel hook. This ensures that even if you forget to run a manual check, Sentinel will catch security threats during `git push`.

**New Behavior:** The hook now **blocks** the push if threats are detected. If you are an agent acting autonomously and are certain the push is safe, you must use the bypass: `SENTINEL_BYPASS=1 git push`.
*Note: To prevent fragile automation breaks, always use `SENTINEL_BYPASS=1` only when absolutely necessary and verified.*

**CRITICAL: DO NOT MODIFY SENTINEL SOURCE CODE**
AI Agents are authorized to **use** Sentinel CLI but must **NEVER** attempt to modify its source files (like `db.js` or `index.js`). If a command fails, report it to the human user instead of attempting a code fix. Automatic fixes by agents often break encoding or introduce syntax errors.

**The "Agentic Skill" Protocol:**
1.  **Link the Repo**: `sentinel link . <owner/repo>`
2.  **Protect Folders**: `sentinel protected add secrets/ --json`
3.  **Install the Skill**: `sentinel hook-install --json`

### CLI Reference for Agents
| Command | Purpose | Example |
| :--- | :--- | :--- |
| `sentinel prepush` | Advisory pre-push analysis | `sentinel prepush --json` |
| `sentinel link <path> <repo>` | **Link a repository** | `sentinel link . owner/repo` |
| `sentinel heal --leaks` | Unstage protected files | `sentinel heal --leaks` |
| `sentinel heal --threats` | Quarantine malware | `sentinel heal --threats` |
| `sentinel protected add <path>` | Mark folder as sensitive | `sentinel protected add config/` |
| `sentinel hook-install` | Enable advisory push scan | `sentinel hook-install --json` |

---

## Agentic AI Interoperability / Interoperabilidad para Agentes de IA

Sentinel 3.2 is optimized for AI Agent workflows. Below are the recommended prompts for seamless integration.

### Global System Instructions / Instrucciones de Sistema Globales

Copy and paste the appropriate block into your agent's system configuration.

**[English]**

> Act as a senior software security engineer. This repository uses Sentinel v3.2 for SAST, binary analysis, and Sandbox protection. Before performing any commit or push, you MUST execute `sentinel audit .` and `sentinel analyze --local` using the `--json` flag. If Sentinel reports threats (INFECTED status) or severe risk alerts, stop execution and request human guidance. Do not attempt to bypass protected file restrictions without explicit authorization.

**[Espanol]**

> Actua como un ingeniero de software senior con enfoque en seguridad. Este repositorio utiliza Sentinel v3.2 para proteccion SAST, analisis binario y analisis de Sandbox. Antes de realizar cualquier operacion de persistencia (commit o push), es obligatorio ejecutar `sentinel audit .` y `sentinel analyze --local` utilizando siempre la bandera `--json`. Si Sentinel reporta amenazas identificadas como INFECTED o alertas de riesgo severo, deten la ejecucion y solicita revision humana. No intentes saltar las protecciones de archivos clasificados sin autorizacion explicita.

### First-Use Onboarding / Onboarding de Primer Uso

**[English]**

> Hello. This project is protected by Sentinel. Your first task is to verify the global security state. Run `sentinel audit .` to perform a deep scan of the current folder and `sentinel config view --json` to understand the active security heuristics. Report any critical findings before proceeding with development tasks.

**[Espanol]**

> Hola. Este proyecto esta protegido por Sentinel. Tu primera tarea es verificar el estado de seguridad global. Ejecuta `sentinel audit .` para realizar un escaneo profundo de la carpeta actual y `sentinel config view --json` para entender las heuristicas de seguridad activas. Reporta cualquier hallazgo critico antes de proceder con tareas de desarrollo.

### Phase 3.2 Hardening Log

Detection capabilities validated against advanced evasion vectors:

| Vector | Technique | Detection Result |
|:---|:---|:---|
| Proxy-Wrapped Sinks | `new Proxy(child_process, handler)` with `get` traps | DETECTED (PROXY_WRAPPED_SINK, CRITICAL) |
| Obfuscated Sink Names | `['e','x','e','c'].join('')` and `String.fromCharCode` | DETECTED (OBFUSCATED_SINK_CONSTRUCTION, CRITICAL) |
| Prototype Pollution | `JSON.parse('{"__proto__": ...}')` + `Object.assign` | DETECTED (PROTOTYPE_POLLUTION_JSON_PAYLOAD, CRITICAL) |
| WASM C2 Beacon | Embedded URLs in `.wasm` binary assets | DETECTED (Embedded URL in Binary Asset, CRITICAL) |
| Invalid Binary Magic | `.wasm` file without valid WebAssembly header | DETECTED (Invalid WASM Magic Bytes, CRITICAL) |
| Dynamic Global Access | `global['ev' + 'al']` or `window[variable]` | DETECTED (DYNAMIC_GLOBAL_ACCESS, HIGH) |

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

**Code of Conduct**: All participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
**Security Reports**: Use [GitHub Security Advisories](https://github.com/javier20dev25/Sentinel/security/advisories/new) to report vulnerabilities privately.

---

*Sentinel: Because your code deserves an uncompromising guardian.*
