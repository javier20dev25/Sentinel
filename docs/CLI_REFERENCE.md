# Sentinel CLI Reference (v3.7.1)

The `sentinel` command-line interface provides developers with a deterministic security decision engine. Version 3.7 introduces the **Risk Intelligence Orchestrator** and **Oracle Mode** for privacy-preserving audits.

---

## 🛠️ Main Scanning Engine

### `sentinel scan <target>`
**The primary multi-signal analysis engine.**

Analyzes the target path (directory or file) across 8 layers of security logic and aggregates findings into a probabilistic risk score.

- **Oracle Mode**: Automatically resolves repository ownership. If the user lacks 2+ authorization signals, the output is quantized, jittered, and redacted to prevent information leakage.
- **Risk Bands**: Categorizes findings into tactical bands (**P0-P4**) with specific recommended actions.
- **ROI Metrics**: Estimates the reduction in compromise probability if findings are remediated.

**Options**:
- `--profile <balanced|strict|relaxed>`: Adjust the risk aggregation sensitivity.
- `--scan-mode <DEFAULT|DEEP|FORENSIC>`: **New in v3.7.1**. Context-aware scanning profile (Limits, Exclusions, and Depth).
- `--allow-external`: Permits scanning directories outside the current CWD.
- `--report <adapter=path>`: Inject external signals (e.g., `npm audit` JSON) into the risk orchestrator.

#### Example: Oracle Mode Warning
```text
🔍 Checking GitHub CLI auth status...
⚠  LIMITED INTELLIGENCE MODE
This repository is not verified as owned/authorized.
Ownership confidence: LOW (1/4 signals)
Detailed findings will be redacted. 
```

- **Performance Dashboard**: Real-time breakdown of I/O efficiency, processing speed (files/sec), and skipped file metrics (binary, large, cached).

---

## 🛠️ Scan Modes (Intelligence Profiles)

| Mode | Max File Size | Depth | Behavior |
| :--- | :--- | :--- | :--- |
| **DEFAULT** | 1 MB | Standard | High signal-to-noise. Skips non-code assets and build artifacts. |
| **DEEP** | 5 MB | Extended | Includes documentation and auxiliary configs. Slower I/O. |
| **FORENSIC** | Unlimited | Maximum | Scans EVERY file (including binary blobs and `.git`). No exclusions. |

---

## 🛠️ Supplemental Security Commands

### `sentinel explain <file>`
Provides a scientific rationale for specific security findings. In Oracle Mode, this output is limited to high-level risk band descriptions.

---

## 🔬 Sandbox & Remote (Sentinel 3.0)

### `sentinel sandbox [command]`
Management of dynamic analysis in isolated environments (GitHub Actions).

- **`generate`**: Displays the `sentinel-sandbox.yml` template for manual setup.
- **`sync`**: Installs or updates the sandbox workflow in the linked repo.
    - `--auto`: Auto-install via git push.
- **`trigger <repo> [branch]`**: Dispatches an analysis run.
    - `--async`: Dispatches the run and returns the Run ID immediately.
- **`status <repo> [runId]`**: Queries current execution state.
- **`analyze <repo> <runId>`**: Downloads and evaluates telemetry signals.

#### Example: Successful Analysis
```text
🚀 Triggering sandbox analysis for owner/repo on branch main...
✅ Run triggered! ID: 12345678
🔗 URL: https://github.com/owner/repo/actions/runs/12345678
⏳ Waiting for analysis to complete...
   [STATUS] completed (success)
✅ Analysis completed successfully. Fetching results...
🔍 Analyzing telemetry...
✅ [SAFE] No malicious behavior detected.
```

---

## ⚙️ Logic & Normalization
Sentinel uses **Cross-Platform Path Normalization**. All paths are normalized to lowercase with forward slashes (`/`), ensuring consistent protection between Windows and Unix environments.

**AI Support**: Use the `--json` flag on any command for machine-readable output.
