# Analytical Methodology and Threat Detection Architecture

This document presents the formalized methodology and internal architecture implemented within the Sentinel static application security testing (SAST) and dynamic hybrid engine. The approaches described herein address modern evasion techniques, supply chain vulnerabilities, and arbitrary code execution vectors.

## 1. Static Abstract Syntax Tree (AST) Inspection and Data Flow Analysis

Static analysis relying solely on regular expressions is insufficient against obfuscated payloads and dynamically constructed strings. The engine utilizes an Abstract Syntax Tree (AST) parser (Acorn) to evaluate code structurally, effectively neutralizing variable renaming and string fragmentation.

### 1.1 Source-to-Sink Taint Tracking
A fundamental requirement for identifying Remote Code Execution (RCE) is tracing untrusted input to critical sinks. The engine implements a lightweight taint analysis module:
- **Sources**: HTTP request bodies (`req.body`), URL parameters (`req.query`), process arguments (`process.argv`), and standard input streams.
- **Sinks**: Dynamic execution environments including `eval()`, `new Function()`, `child_process.exec()`, and `subprocess.Popen()`.
- **Mechanism**: The AST inspector traverses `CallExpression` nodes. If a critical sink is identified, arguments are evaluated against known source identifiers. Direct flows are flagged as critical RCE vectors, distinguishing them from potentially benign uses of `eval`.

### 1.2 Geofencing and Environment Evasion Detection
Sophisticated malware often queries the execution environment to avoid detonating within security sandboxes or specific geographical locales (e.g., checking for Russian or Chinese IP spaces/locales). 
The structural analyzer identifies programmatic access to:
- `process.env.TZ`, `process.env.LANG`, and `LC_ALL`.
- Browser or headless environment objects such as `navigator.language`.
- Internal formatting APIs like `Intl.DateTimeFormat().resolvedOptions().timeZone`.
Access to these primitives without clear application logic justification is flagged as an evasion attempt.

## 2. Supply Chain and Lockfile Integrity

Supply chain attacks frequently inject malicious code outside of the primary source files, targeting dependency manifests and lockfiles.

### 2.1 Dependency Risk Matrix
A qualitative scoring mechanism evaluates dependency declarations in `package.json` and lockfiles rather than relying solely on binary alerts.
- **Unpinned Versions (`latest`, `*`)**: Assigned high risk due to the lack of deterministic installation, making the repository immediately susceptible to newly published malicious package versions.
- **Floating Versions (`^`, `~`)**: Assigned medium risk. While constrained to semver boundaries, they still permit the silent absorption of compromised minor/patch updates.
- **Typosquatting Anomalies**: Lexical comparison algorithms identify packages resembling highly utilized libraries (e.g., `lodasb` instead of `lodash`), attributing critical risk scores upon pattern matches.

### 2.2 Manifest Tampering and Dropper Discovery
The engine parses `package-lock.json` and `pnpm-lock.yaml` to detect:
- **Registry Poisoning**: Resolved URLs pointing to non-standard or unauthorized registries (bypassing `registry.npmjs.org`).
- **Phantom Dependencies**: Packages present in the lockfile but absent from the primary declarative manifest (`package.json`), indicating offline injection.
- **Missing Integrity Hashes**: The absence of SRI (Subresource Integrity) hashes in resolved registry packages, a strong indicator of local manifest manipulation prior to commit.

## 3. Dynamic Execution Interception (X-Ray Engine)

To counter advanced obfuscation (e.g., Dean Edwards' packers, base64-encoded strings wrapped in `atob()`, and split string payloads), Sentinel integrates a dynamic execution pipeline (Sandbox).

### 3.1 Runtime Monkey-Patching
The Sandbox workflow utilizes Node.js mechanisms to inject a telemetry script (`sentinel-xray.js`) prior to dependency installation. This script overrides global execution primitives:
- `global.eval`
- `global.Function`
- `child_process.exec`

By proxying these functions, the engine intercepts the execution call stack in runtime. When an obfuscated payload decodes itself and attempts to evaluate the resulting string, the proxy intercepts and outputs the decrypted plain-text payload to the execution log, neutralizing the obfuscation without persisting malicious state modifications to the host.

### 3.2 Deterministic Locale Spoofing
To force environment-sensitive malware to detonate, the Sandbox workflow implements controlled environmental spoofing profiles:
- **evasion-detect**: Overrides the virtual machine timezone (`TZ=Europe/Moscow`) and language (`LANG=ru_RU.UTF-8`). 
- **aggressive**: Iterates through multiple regions and user-agent modifications.
These profiles are deterministically applied, allowing researchers to observe disparate malware behavior based on geographical assumptions.

## 4. Mitigation of Homoglyph and Unicode Evasion
The engine scans for specific directional formatting characters (e.g., `\u202A` to `\u202E`, Zero-Width Spaces) associated with Trojan Source attacks (CVE-2021-42574). These BiDi overrides manipulate the visual rendering of the code, making malicious logic appear as benign comments to human reviewers. Detection occurs at the bytecode level, prioritizing raw character matrices over visually rendered diffs.

## 5. High-Velocity Heuristic Partitioning (Fast Mode)

To facilitate near-instantaneous feedback during ingestion or pre-commit hooks, Sentinel implements a High-Velocity Heuristic Partitioning strategy (`--fast`). This approach optimizes throughput by performing a non-exhaustive, targeted scan of the most critical threat vectors.

### 5.1 Hybrid Filtering Logic
The Fast Mode logic deviates from standard full-depth scans by applying a two-tier hybrid filter:
- **Severity Thresholding**: The engine restricts rule execution to heuristics with a calibrated risk score of `severity >= 8`. This effectively isolates critical-impact findings while skipping low-confidence or informational signals.
- **Deterministic Allowlist**: To prevent false negatives resulting from score recalibrations, specific high-order families are mandatorily included. This includes all rules within the `EXEC`, `NET`, `EXFIL`, and `obfuscation` namespaces.

### 5.2 Computational Optimizations
Latency is further reduced through structural and search optimizations:
- **Depth Restriction**: Recursive directory traversal is capped at `depth=1` to focus on project-root entry points and primary source manifests.
- **Entropy Skip**: High-entropy data calculations (sensitive in massive files) are bypassed in favor of pattern-based secret discovery.
- **Sandbox Isolation**: Dynamic execution analysis is disabled, prioritizing static structural analysis for sub-second response times.
