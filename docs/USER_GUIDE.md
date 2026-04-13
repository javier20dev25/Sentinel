# Sentinel User Guide

## 🇪🇸 Resumen Ejecutivo (Spanish)
La versión 3.0 de Sentinel incorpora una infraestructura de **Sandbox Dinámico** remota para la validación proactiva de dependencias. Esta funcionalidad permite ejecutar y auditar el proceso de instalación de paquetes en entornos aislados (GitHub Actions), proporcionando visibilidad sobre el comportamiento en tiempo de ejecución, como conexiones de red y modificaciones en archivos críticos, antes de su integración en el entorno local.

---

## Introduction
Sentinel is a proactive security suite designed to protect your GitHub repositories from within your local machine. This guide covers the core security modules and how to use the interactive dashboard effectively.

---

## 🔐 Mastering Authentication
Upon the first launch of the **Sentinel Web Edition** or **Standard Edition**, you will be prompted to set a **Master Password**.

> [!IMPORTANT]
> The Master Password is the only way to override **Asset Guard** blocks and access the system settings. It is hashed locally using Argon2/Bcrypt and never leaves your machine.

---

## 🛡️ Sentinel Project Shield (SPS)
**Project Shield** is a core module that performs static analysis and environment hardening.

### Core Features:
- **Environment Hardening**: Automatically runs `npm config set ignore-scripts true` for the linked project to prevent malicious scripts from executing during installation.
- **Dependency Audit**: Scans your `package.json` for known-malicious patterns and registry overrides.
- **Dynamic Validation**: Leverages the Sandbox to analyze dependency behavior in a simulated environment.

---

## 🛡️ Asset Guard (SAG)
**Asset Guard** intercepts Git operations to prevent the accidental leakage of sensitive files.

### How it works:
1. **Selection**: Define specific files or patterns as "Prohibited" (e.g., `.env`, `*.pem`).
2. **Interception**: Sentinel checks staged changes against the prohibited list before a `git push`.
3. **Control**: Violations result in an immediate block of the Git operation.
4. **Override**: Force a push by entering your **Master Password** only if the leakage is intentional.

---

## 📊 Global Audit Trail (SGA)
The **Audit Trail** provides an immutable record of security events within the application.

- **Event Logging**: Every scan result and threat detected is logged with high-precision timestamps.
- **Traceability**: Logs are linked to specific Git commit hashes and user identities.
- **Data Integrity**: Sensitive data captured during audits (e.g., partial tokens) is sanitized before storage.

---

## 🔬 Scanning Engine
Sentinel's engine operates in three main modes:
1. **Manual Scan**: Triggered via the UI for the entire repository.
2. **Dynamic Sandbox**: Behavioral analysis of the runtime environment during package installation.
3. **Git Safe Staging**: Scans only the files currently staged in Git before a commit.

> [!TIP]
> Use the **Sandbox Monitor** tab in the dashboard to review historical simulations and behavioral signals detected by the Dynamic Sandbox engine.
