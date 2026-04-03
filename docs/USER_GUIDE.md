# Sentinel User Guide

## Introduction
Sentinel is a proactive security suite designed to protect your GitHub repositories from within your local machine. This guide covers the core security modules and how to use the interactive dashboard effectively.

---

## 🔐 Mastering Authentication
Upon the first launch of the **Sentinel Web Edition** or **Standard Edition**, you will be prompted to set a **Master Password**.

> [!IMPORTANT]
> The Master Password is the only way to override **Asset Guard** blocks and access the system settings. It is hashed locally using Argon2/Bcrypt and never leaves your machine.

---

## 🛡️ Sentinel Project Shield (SPS)
**Project Shield** is the most advanced module of Sentinel. it performs deep static analysis and environment hardening.

### Core Features:
- **Environment Hardening**: Automatically runs `npm config set ignore-scripts true` for the linked project. This prevents malicious `postinstall` or `preinstall` scripts from executing during package installation.
- **AST Leak Detection**: Scans your `package.json` for known-malicious dependency patterns and obfuscated scripts.
- **Dependency Sandboxing**: Analyzes dependencies before they are allowed to interact with your local environment.

---

## 🛡️ Asset Guard (SAG)
**Asset Guard** proactively intercepts Git operations to prevent the leakage of sensitive data.

### How it works:
1. **Selection**: You mark specific files or patterns as "Prohibited" (e.g., `.env`, `*.pem`, `service-account.json`).
2. **Interception**: When you attempt a `git push` via the dashboard, Asset Guard checks your staged changes against the prohibited list.
3. **Control**: If a violation is found, the push is **BLOCKED** immediately.
4. **Override**: You can only force a push of these assets by entering your **Master Password**, ensuring that accidental leaks are impossible.

---

## 📊 Global Audit Trail (SGA)
The **Audit Trail** provides a 100% immutable record of every security event within Sentinel.

- **Event Integrity**: Every scan, threat detected, and git operation is logged with a high-precision timestamp.
- **Traceability**: Logs are linked to specific Git commit hashes and GitHub user identities.
- **Sanitization**: Sensitive data captured during analysis (like partial tokens) is automatically sanitized before being stored in the Audit Trail.

---

## 🔬 Scanning Engine
Sentinel's engine operates in three modes:
1. **Manual Scan**: Triggered via the UI for the entire repository.
2. **PR Watchman**: Automatically fetches and analyzes incoming Pull Request diffs in memory.
3. **Git Safe Staging**: Scans only the files you have currently staged in Git before you commit.

> [!TIP]
> Use the **Git Safe Staging** view in the dashboard to review exactly what you are about to push to GitHub.
