# 🛡️ Sentinel Detection Specification (v1.0)

> This document is a human-readable mirror of the `sentinel-spec.json` configuration file. It outlines the formal bounds, rulesets, and scoring metrics used by the Sentinel Threat Engine. By relying on a configuration file rather than hardcoded logic, Sentinel aligns with 12-factor principles, allowing security analysts to adjust rules without re-deploying code.

## 1. Data Flow Analysis (AST Taint Tracking)

The Static AST Engine evaluates JavaScript traces to find paths where external, untrusted input reaches critical execution nodes.

| Concept | Identified Vectors in Engine |
| :--- | :--- |
| **Sources** | `req.query`, `req.body`, `process.argv`, `req.headers`, `input`, `fs.readFileSync` |
| **Sinks** | `eval()`, `exec()`, `setTimeout()`, `setInterval()`, `new Function()`, `child_process.spawn()` |

### 📊 Scoring Weights
- **Heuristic Direct Sink Match**: Warning Level (Risk: 8/10)
- **Tainted Data Flow (Source → Sink)**: Critical Severity (Risk: 10/10)

## 2. Geofencing & Locale Spoofing

Detects behaviors common in malware attempting to evade analysis by verifying it is not running in a specific locale (e.g., Russian ransomware avoiding CIS countries).

| Inspected Objects | Monitored Properties | Severity |
| :--- | :--- | :--- |
| `process.env` | `TZ`, `LANG`, `LC_ALL` | HIGH (8/10) |
| `navigator` | `language`, `languages`, `geolocation` | HIGH (8/10) |
| `Intl` | `DateTimeFormat` | HIGH (8/10) |

## 3. Dependency Risk Scoring (Lockfile Analysis)

Instead of binary alerts, NPM/Yarn dependencies are scored dynamically.

### 📦 Versioning Risks
- **Floating Packages (`^`, `~`)**: +20 Risk Weight (Severity: WARNING)
- **Unpinned / Wildcard Packages (`latest`, `*`)**: +60 Risk Weight (Severity: HIGH)

### 👻 Typosquatting Analysis
- Compares base dependency names against a matrix of known high-value targets (e.g., `lodash`, `react`).
- **Detected Anomaly Risk Weight**: +90 (Severity: CRITICAL)

## Architectural Principle
Any changes to these metrics, vectors, or targets MUST be placed into `rules/sentinel-spec.json`. Do not edit the core JavaScript parsers to add new rules or weights.
