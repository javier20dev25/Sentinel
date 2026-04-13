# Sentinel 3.0: Dynamic Sandbox Guide

## Overview
The Dynamic Sandbox in Sentinel 3.0 provides behavioral analysis of package dependencies by executing them in isolated, ephemeral environments (GitHub Actions). This allows for the detection of threats that are typically invisible to static analysis, such as obfuscated payloads, binary droppers, and runtime network exfiltration.

---

## ⚖️ Static Analysis vs. Sandbox: When to use each

Sentinel provides both static and dynamic analysis. Understanding when to use each is key to maintaining a secure supply chain without incurring unnecessary compute costs.

| Feature | Static Analysis (AST/Heuristics) | Dynamic Sandbox |
|---|---|---|
| **Best For** | Every commit and Pull Request. | High-risk PRs or new dependencies. |
| **Speed** | Near-instant. | 3-10 minutes (CI overhead). |
| **Visibility** | Code structure, credentials, known patterns. | Network connections, lockfile integrity, binary behavior. |
| **Cost** | Minimal (Local CPU). | GitHub Actions minutes. |
| **Usage** | Mandatory first line of defense. | Targeted validation for suspicious assets. |

---

## 🔄 Recommended Full Flow

To implement the sandbox in your workflow, follow these steps in order:

1. **Generate Workflow**:
   Run `sntl sandbox generate` to obtain the latest YAML template.
2. **Setup Repository**:
   Create `.github/workflows/sentinel-sandbox.yml` in your repository and push it to the main branch.
3. **Trigger Analysis**:
   When a new dependency is added, run `sntl sandbox trigger <repo> <branch> --wait` to start the simulation.
4. **Evaluate Results**:
   Review the terminal output or the **Sandbox Monitor** in the UI to confirm the package is safe before merging.

---

## 🛡️ "Passive Mode" Operation
Sentinel implements a **Passive Mode** security model. This means Sentinel does not require write permissions to your repository. Instead, it relies on a pre-installed workflow file that is triggered via the `workflow_dispatch` API.

This model ensures that even if the local Sentinel environment is compromised, the attacker cannot modify your remote CI/CD configuration without your manual review and commit of the workflow file.

---

## 🔬 Use Case: Investigating the "Axios 2026" Attack
The "Axios 2026" attack utilized a compiled WebAssembly (WASM) module to hide malicious logic from static scanners. By using the sandbox, Sentinel can detect the execution artifacts of such an attack.

### Realistic Evaluation Output (`sntl sandbox analyze`)
When analyzing a repository infected with this pattern, the output will look as follows:

```text
📥 Downloading artifacts for run #99283741...
🔍 Analyzing telemetry...

🚨 FOUND 3 SUSPICIOUS BEHAVIORS IN SANDBOX:

[CRITICAL] RUNTIME_REGISTRY_OVERRIDE
Message: [SANDBOX] La variable npm_config_registry apunta a un registry NO oficial.
Evidence: npm_config_registry = https://malicious-registry.host/repo/ ...

[HIGH] UNEXPECTED_NETWORK_CONNECTIONS
Message: [SANDBOX] 1 conexión(es) de red nuevas detectadas durante npm install en axios/axios.
Evidence: > tcp 45.33.22.11:443 [ESTABLISHED] (Domain: sfrclak.com) ...

[HIGH] WASM_MODULE_DETECTED
Message: [SANDBOX] 1 archivo(s) .wasm encontrados en node_modules de axios/axios.
Evidence: node_modules/axios/lib/core/auth.wasm ...

Risk Score: 10.0/10

[RECOMMENDATION]
The analysis indicates a highly compromised installation environment.
1. DO NOT install or merge this version.
2. Verify the source registry in your .npmrc file.
3. Audit the detected WASM module for malicious entry points.
```

---

## 🔍 Troubleshooting

### Error: "Workflow not found" (404)
- **Cause**: The `sentinel-sandbox.yml` file is missing or wrongly named in the remote `.github/workflows/` directory.
- **Solution**: Ensure the file exists in the default branch. Run `sntl sandbox generate` to verify the required filename.

### Error: "Secondary Rate Limit" (403)
- **Cause**: Frequent API calls to GitHub in a short period.
- **Solution**: Run `gh auth refresh -s workflow` to ensure your token is fresh. If the error persists, wait 60 seconds before re-triggering.

### Empty Telemetry Artifacts
- **Problem**: The run completed, but the `sentinel-telemetry` artifact is empty or missing.
- **Solution**: Check the GitHub Actions logs for your repository. If the `npm install` step failed before telemetry could be captured, investigate the build logs for specific dependency errors.

### Harden-Runner Compatibility
- **Problem**: No network egress logs are present in the report.
- **Solution**: Harden-Runner is required for advanced egress auditing. If using a private runner or a non-standard environment, ensure that the `step-security/harden-runner@v2` step is correctly configured in your YAML.
