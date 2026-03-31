# Sentinel: Architecture Deep Dive

## Security Model: Zero-Trust Static Analysis

Sentinel is designed with a "Never Trust, Always Verify" approach to repository changes.

### 1. Analysis in Memory
Sentinel uses the `gh pr diff` command to fetch changes directly from the GitHub API. 
**Impact**: The malicious code is never written to a file with an executable extension on the developer's disk during the scan, preventing accidental execution by IDEs or file watchers.

### 2. Detection Layers

#### Layer 1: Unicode & Homeograph Filter
Detects characters that are visually identical or invisible to humans. 
- **Regex Detection**: Searches for zero-width spaces, joiners, and non-joiners.
- **Severity**: High/Critical if consecutive characters are found (common in obfuscated payloads).

#### Layer 2: Entropy & Structure
Detects obfuscation by analyzing the density of data.
- **Line Length**: Flags lines that exceed standard coding practices (1000+ chars).
- **File Density**: Flags lines that contain a disproportionate amount of the file's information.

#### Layer 3: Environment Guardian
Inspects the `package.json` and shell environment.
- **Script Analysis**: Detects dangerous commands (`curl`, `eval`, `fetch`) inside lifecycle scripts (`preinstall`, `postinstall`).
- **npm Enforcer**: Automatically runs `npm config set ignore-scripts true` to prevent script execution during package installation.

### 3. Background Watchman
The background process (polling) ensures that even if you miss a browser notification from GitHub, your local system tray will alert you before you run `git pull`.

---
*Created by Antigravity for Sentinel Project.*
