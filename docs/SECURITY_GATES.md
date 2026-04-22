# Sentinel Security Gates & Decision Logic

Sentinel functions as an **Auditable Decision Engine** for CI/CD pipelines. It uses an adaptive security model that escalates its depth of analysis based on the perceived risk of the changes.

## 1. Adaptive Gate Levels

Sentinel automatically determines the required "Gate Level" by analyzing the files in a pull request or local commit.

| Level | Name | Trigger | Depth |
| :--- | :--- | :--- | :--- |
| **0** | **FAST** | Minor source changes | Surface-only, fast heuristics. |
| **1** | **STANDARD** | General source changes | Full AST & Entropy analysis. |
| **2** | **DEPENDENCY** | `package.json`, lockfiles | Transitve dependency audit & checksums. |
| **3** | **ARTIFACT** | `.wasm`, `.exe`, `.dll`, etc. | Binary masquerading & deep entropy check. |
| **4** | **FORENSIC** | High suspicion or `--forensic` | Scans `node_modules`, hidden files, and junk. |

## 2. Decision Categories

Sentinel distinguishes between two types of findings to facilitate granular pipeline orchestration:

### 🔴 [SECURITY] Findings
- **Description**: Heuristic or scientific detection of an active threat (malware, backdoors, C2 vectors).
- **Examples**: `eval(atob(...))`, `reverse_shell`, `exfiltration_request`.
- **Exit Code**: `1`

### 🟣 [POLICY] Violations
- **Description**: Violations of the project's security structure or CI/CD governance rules.
- **Examples**:
    - **Binary Masquerading**: A binary file with a false extension (e.g. `.wasm` named as `.txt`).
    - **Supply Chain Anomaly**: Unauthorized modification of a lockfile or dangerous `postinstall` script.
    - **Artifact Presence**: Inclusion of unapproved binary assets in the repository.
- **Exit Code**: `2`

## 3. Exit Code Contract (0-3)

| Code | Status | Meaning |
| :---: | :---: | :--- |
| **0** | **PASS** | No threats found. Clean to merge. |
| **1** | **SECURITY** | Security threats found (Engine SARB). |
| **2** | **POLICY** | Governance or Gate violations found. |
| **3** | **ERROR** | Internal execution error. |

## 4. CI/CD Integration Examples

### Simple Block
```bash
sentinel scan . --ci
```

### Advanced Orchestration (Bash)
```bash
sentinel scan . --ci
RESULT=$?

if [ $RESULT -eq 1 ]; then
  echo "🚨 Security threat detected! Escalate to Security Team."
  exit 1
elif [ $RESULT -eq 2 ]; then
  echo "⚠️ Policy violation. Manual review required by DevOps."
  exit 1
fi
```

## 5. Forensic Audit

For high-security environments or post-incident analysis:
```bash
sentinel audit --forensic
```
This mode overrides all exclusion lists (including `node_modules`) to find hidden payloads, masqueraded binaries, and dropped artifacts across the entire repository tree.
