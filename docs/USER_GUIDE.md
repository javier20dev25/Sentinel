# Sentinel User Guide

## 🇪🇸 Resumen Ejecutivo (Spanish)
La versión 3.0 de Sentinel incorpora una infraestructura de **Sandbox Dinámico** remota para la validación proactiva de dependencias. Esta funcionalidad permite ejecutar y auditar el proceso de instalación de paquetes en entornos aislados (GitHub Actions), proporcionando visibilidad sobre el comportamiento en tiempo de ejecución, como conexiones de red y modificaciones en archivos críticos, antes de su integración en el entorno local.

---

## Introduction
Sentinel is a proactive security suite designed to protect your GitHub repositories from within your local machine. It combines static analysis, dynamic sandbox simulations, and real-time Git interception.

---

## 🔐 Mastering Authentication
Upon the first launch of the **Sentinel Web Edition**, you will be prompted to set a **Master Password**.

> [!IMPORTANT]
> The Master Password is used to encrypt local settings and protect the integrity of your security rules. It is hashed locally and never leaves your machine.

---

## 🛡️ Sentinel Project Shield (SPS)
**Project Shield** is a core module that performs static analysis and environment hardening.

### Core Features:
- **Environment Hardening**: Automatically runs `npm config set ignore-scripts true` for the linked project to prevent malicious scripts from executing during installation.
- **Dependency Audit**: Scans your `package.json` for known-malicious patterns and registry overrides.
- **Dynamic Validation**: Leverages the Sandbox to analyze dependency behavior in a simulated environment.

---

## 🛡️ Asset Guard (SAG) - Advisory Mode
**Asset Guard** monitors Git operations to prevent the accidental leakage of sensitive files (keys, .env, private configs).

### How it works:
1. **Selection**: Use `sentinel protected add <path>` to mark folders or files as sensitive.
2. **Analysis**: Sentinel checks staged changes AND unpushed commits for prohibited files.
3. **Advisory**: Instead of "hard blocking" which can break Windows Git workflows, Sentinel provides a **Security Advisory**.
4. **Visibility**: If a leak is found, the CLI will output a clear report and a legal disclaimer. The responsibility to proceed or fix (using `sentinel heal`) stays with the developer or AI agent.

> [!TIP]
> Use `sentinel heal --leaks` to automatically remove protected files from your staging area or current commit if they were included by accident.

---

## 📊 Global Audit Trail (SGA)
The **Audit Trail** provides an record of security events.

- **Event Logging**: Every scan result and threat detected is logged with high-precision timestamps.
- **Traceability**: Logs are linked to specific Git commit hashes and user identities for accountability.
- **Sanitization**: Sensitive data captured during audits (e.g., partial secrets) is sanitized before storage.

---

## 🔬 Scanning Engine
Sentinel's engine operates in three main modes:
1. **Manual Scan**: Triggered via `sentinel scan` or the UI.
2. **Pre-Push Advisory**: Triggered automatically before a push via the Sentinel Hook.
3. **Dynamic Sandbox**: Behavioral analysis of the runtime environment during package installation.

> [!TIP]
> Use the **Sandbox Monitor** tab in the dashboard to review historical simulations and behavioral signals detected by the Dynamic Sandbox engine.

---

*Sentinel: Because your code deserves an uncompromising guardian.*
