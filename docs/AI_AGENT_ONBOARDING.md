# 🤖 Sentinel: AI Agent Onboarding Guide (v3.8.0)

Welcome, Agent! This guide is a **mandatory protocol** to ensure you operate within the security boundaries of Sentinel v3.8.

> **CRITICAL RULE**: You are authorized to **use** Sentinel via CLI commands. You must **NEVER** modify Sentinel's source code files. You are **PROHIBITED** from declassifying data (`protected remove`) unless explicitly instructed by a human.

---

## 📋 Recommended Workflow

### Step 1: Initialize Sentinel Guard
Always start your session by enabling the installation firewall.
```bash
sentinel guard enable
```
This ensures any package installation you attempt will be automatically audited.

### Step 2: Manage Dependencies via Firewall
Never use `npm install` directly. Use the Sentinel Trust Engine:
```bash
sentinel install npm <package>
```

### Step 3: Protect Sensitive Assets (Classification)
Mark directories that should never be pushed to GitHub.
```bash
sentinel protected add .env --json
```
Check what's currently classified:
```bash
sentinel protected list --json
```
*See the **[Classified Data Guide](CLASSIFIED_DATA_GUIDE.md)** for the declassification protocol.*

### Step 4: Pre-Push & Pre-Commit Verification
Before suggesting a commit or push, verify the outbound security:
```bash
sentinel prepush --json
sentinel scan . --json
```

---

## 🔄 AI Operational Protocol

1. **Before any installation**: Use `sentinel install`.
2. **If a package is SUSPICIOUS**: Run `sentinel verify-pkg <adapter> <pkg> --sandbox`.
3. **Before every push**: `sentinel prepush --json`.
4. **Data Privacy**: Respect Oracle Redaction. Do not attempt to bypass intelligence masking.

---

## ⚡ Quick Command Reference (v3.8)

| Command | Purpose |
| :--- | :--- |
| `guard enable` | Enable OS-level package manager interception |
| `install <adapter> <pkg>` | Verify and install a package through the firewall |
| `trust add <pkg>` | Mark a package as trusted in the local cache |
| `protected add <path>` | Classify a file/folder as sensitive |
| `prepush` | Analyze commits before pushing (Advisory) |
| `sandbox sync --auto` | Generate & auto-push sandbox workflow |

---

## 📖 Essential Reading for Agents

- **[Sentinel AI Protocol (Prompt)](../AGENT.md)** — Use this in your system prompt.
- **[Classified Data Guide](CLASSIFIED_DATA_GUIDE.md)** — Protocol for sensitive data.
- **[Supply Chain Guide](SUPPLY_CHAIN_GUIDE.md)** — How the firewall works.
- **[Architecture](ARCHITECTURE.md)** — System design.

---

*By following these steps, you protect the human's infrastructure while you build. 🛡️*
