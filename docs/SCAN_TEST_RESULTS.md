# 🧪 Sentinel Scan Test Results (v3.0)

> This document contains the real-time output from the Sentinel Security Engine's latest validation suite. These tests verify the engine's ability to detect high-complexity malware, obfuscation, and data-flow vulnerabilities.

## 🛡️ Static Analysis Engine (SAST)

| File | Detection Pattern | Risk Level |
| :--- | :--- | :---: |
| `malicious_file.js` | Unicode Invisible Homoglyph / Control Char | 9 |
| `obfuscated.js` | High-Entropy Obfuscation (Line Length) | WARNING |
| `package.json` | Malicious Lifecycle Script (Preinstall) | **CRITICAL** |
| `packed_exploit.js` | Packed JavaScript Obfuscation (Dean Edwards) | 9 |
| `reverse_shell.js` | Socket-to-Process Pipe (Reverse Shell) | 10 |
| `data_flow.js` | OS Command Injection via Taint Analysis | 10 |
| `injection.js` | SQLi via Concatenation & Prototype Pollution | 9 |

## 🔑 Secret Detection & Leakage (DLP)

Sentinel scans the filesystem for hardcoded secrets, keys, and tokens using high-confidence entropy analysis.

| Secret Type | Status | Detection Detail |
| :--- | :--- | :--- |
| **AWS Credentials** | ✅ Clean | No leaks found in `.tf` config. |
| **OpenAI API Key** | 🔴 DETECTED | Identified project API key (Risk 10). |
| **JWT / Bearer Token** | 🔴 DETECTED | Identified hardcoded JWT (Risk 8). |
| **Private Keys** | 🔴 DETECTED | RSA/SSH PEM key found in source (Risk 10). |
| **Stripe Keys** | ✅ Clean | Clean in `.js` test file. |

---

## Technical Audit Snapshot

**Test Environment:** Windows 10/11 | Node.js v18+ | Sentinel CLI 3.0
**Spec Version:** `sentinel-spec.json v1.0`

*Verified by Sentinel Automated Test Suite.*
