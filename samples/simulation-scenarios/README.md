# 🎯 Sentinel Detection Samples

This directory contains **safe simulation scripts** designed to trigger Sentinel's detection engine for demonstration and testing purposes.

> [!WARNING]
> These scripts simulate malicious behavior patterns. They **do not** perform any actual harmful operations — the commands are structured to be caught and blocked by Sentinel before execution.

## 📂 Scenarios

| File | Attack Type | Detection Vector |
| :--- | :--- | :--- |
| `malicious-postinstall.js` | C2 Callback via Subprocess | Lifecycle Filter + Network Guard |
| `obfuscated-payload.js` | eval() obfuscation chain | AST Inspector (charCode entropy) |

## 🚀 How to Run the Demo

1. **Link Sentinel to this folder:**
   ```bash
   cd /path/to/your/sentinel
   node packages/cli/index.js link
   ```

2. **Run a scan against the samples directory:**
   ```bash
   node packages/cli/index.js scan --path samples/simulation-scenarios
   ```

3. **Expected Output:**
   - `CRITICAL` alert for subprocess C2 connection attempt
   - `HIGH` alert for `eval(String.fromCharCode(...))` pattern
   - Sentinel Risk Score: **9.1/10**

## 💡 What This Demonstrates

Sentinel's multi-layer detection system catches attacks that simple `npm audit` **cannot**:

| Capability | `npm audit` | Sentinel |
| :--- | :---: | :---: |
| Known CVE Matching | ✅ | ✅ |
| Obfuscated Code Detection | ❌ | ✅ |
| Runtime Subprocess Tracking | ❌ | ✅ |
| Network Connection Monitoring | ❌ | ✅ |
| AI Risk Scoring | ❌ | ✅ |
