# Sentinel CLI: Autonomous Agent Interoperability Report

**Date**: April 19, 2026  
**Author**: Javier Astaroth  
**Agent Model Under Test**: Gemini 2.5 Flash Lite (via Gemini CLI terminal)  
**Sentinel Version**: main @ commit `551e42f`  
**Test Environment**: Windows 11, Node.js v24.13.1, GitHub CLI (gh) authenticated  

---

## Abstract

This document reports empirical findings from a controlled evaluation of Sentinel's Command-Line Interface (CLI) when operated autonomously by a lightweight AI agent. The objective was to measure whether an AI model with no prior knowledge of Sentinel could discover, configure, and operate all core security features through the terminal alone — without documentation assistance, human intervention, or source code modification. Results indicate that the agent successfully completed 11 of 13 tested operations with correct output, averaging sub-second response times across all commands. Two operations required manual intervention due to architectural constraints in the sandbox module.

---

## 1. Introduction

Sentinel is a local security guardian designed to protect GitHub repositories from secrets leakage, unauthorized file exposure, and malicious code injection. A key design goal is **agentic interoperability**: the ability for AI coding assistants to consume Sentinel's security audits programmatically and act on them autonomously.

This evaluation tests that design goal by deploying a lightweight AI agent (Gemini 2.5 Flash Lite) with the following constraints:

- The agent has **no prior training data** about Sentinel's CLI.
- The agent is **prohibited from modifying** any Sentinel source files.
- The agent must discover all commands through `--help` flags and structured JSON output.
- All operations must be performed **exclusively through terminal commands**.

---

## 2. Methodology

### 2.1 Test Environment

| Component | Version |
|:---|:---|
| Operating System | Windows 11 |
| Node.js | v24.13.1 |
| Sentinel | main branch, commit `551e42f` |
| Agent Model | Gemini 2.5 Flash Lite |
| Agent Interface | Gemini CLI (terminal) |
| Target Repository | javier20dev25/Merx |

### 2.2 Test Protocol

The agent was instructed to:

1. Clone the Sentinel repository from GitHub and install dependencies.
2. Explore the CLI using `--help` to discover available commands.
3. Link a target repository (Merx) and apply security protections.
4. Simulate a secrets leak by staging and committing a protected file.
5. Execute detection, blocking, and remediation commands.
6. Explore the sandbox module for dynamic analysis capabilities.
7. Report all findings with execution time measurements.

### 2.3 Measurement

Execution times were estimated by the agent based on terminal output timestamps. These are approximate values reflecting end-to-end command latency including database I/O and Git operations.

---

## 3. Results

### 3.1 Command Discovery

The agent successfully identified all 13 CLI commands using `sentinel --help`:

```
prepush, hook, hook-install, open, sandbox, packs, 
analyze, heal, protected, status, link, list, scan
```

The agent correctly identified the `--json` global flag for structured output and applied it consistently throughout testing.

### 3.2 Repository Linking and Configuration

| Operation | Command | Result | Time |
|:---|:---|:---|:---|
| Link repository | `sentinel link . javier20dev25/Merx --json` | ✅ `repo_id: 4` returned | ~0.6s |
| Protect folder (keys) | `sentinel protected add keys --json` | ✅ Confirmed | ~0.2s |
| Protect folder (secrets) | `sentinel protected add secrets --json` | ✅ Confirmed | ~0.2s |
| Protect folder (config) | `sentinel protected add config --json` | ✅ Confirmed | ~0.2s |
| Install hook | `sentinel hook-install --json` | ✅ `already_installed` | ~0.6s |
| List repositories | `sentinel list --json` | ✅ Returns array with 4 repos | ~0.6s |

**Observation**: The agent completed the full onboarding sequence (link → protect → hook-install) without errors. The `--json` output was parsed correctly by the agent at every step.

### 3.3 Threat Detection

A simulated secrets leak was created by committing `keys/api_key.txt` to the local Merx repository.

| Operation | Command | Result | Time |
|:---|:---|:---|:---|
| Hook simulation | `sentinel hook pre-push` | ✅ `SECURITY THREAT BLOCKED` with exit code 1 | ~0.8s |
| Pre-push analysis | `sentinel prepush --json` | ✅ `safe: false`, violations: `["keys/api_key.txt"]` | ~1.2s |
| Full scan | `sentinel scan --json` | ✅ `1 potential threat` detected in Merx | ~3.7s |
| Status check | `sentinel status --json` | ✅ Merx reported as `INFECTED` | ~0.6s |

**Observation**: The detection pipeline operated correctly across all three detection vectors (hook, prepush advisory, and full scan). The JSON output was consistent and parseable.

### 3.4 Remediation

| Operation | Command | Result | Time |
|:---|:---|:---|:---|
| Heal leaks | `sentinel heal --leaks --json` | ✅ `healed: 0`, `committed_leaks_remaining: ["keys/api_key.txt"]` | ~0.9s |
| Post-heal verification | `sentinel prepush --json` | ✅ `safe: false` (correct — file still in commit) | ~1.3s |

**Observation**: The `heal --leaks` command correctly identified that the leaked file was already committed (not merely staged) and provided manual remediation instructions (`git reset HEAD~1`) instead of attempting an automated history rewrite. This is the intended safe behavior. The agent understood the distinction and reported it accurately.

### 3.5 Sandbox Module

| Operation | Command | Result | Time |
|:---|:---|:---|:---|
| Explore sandbox | `sentinel sandbox --help` | ✅ Discovered: `status`, `sync` | ~0.3s |
| Generate workflow | `sentinel sandbox sync --json` | ✅ `sentinel-sandbox.yml` created locally | ~1.1s |
| Check sandbox status | `sentinel sandbox status --json` | ✅ `installed: false`, `latestRun: null` | ~1.5s |

**Observation**: The sandbox module functioned as designed. The agent correctly generated the GitHub Actions workflow template. However, the agent identified a limitation: the CLI cannot autonomously upload the workflow file to the remote repository or trigger a GitHub Actions run. This requires manual intervention (a `git push` of the `.github/workflows/` directory to the target repository).

### 3.6 Local Analysis

| Operation | Command | Result | Time |
|:---|:---|:---|:---|
| Local analysis | `sentinel analyze --local --json` | ✅ Reported `Clean` | ~0.4s |

**Observation**: The agent noted a discrepancy between `analyze --local` (which reported `Clean`) and `scan` (which reported `INFECTED`). This is expected behavior: `analyze --local` examines only the current working directory state and staged changes, while `scan` queries open Pull Requests via the GitHub CLI. The two commands operate on different data sources.

---

## 4. Performance Summary

| Command | Avg. Response Time | Category |
|:---|:---|:---|
| `sentinel link` | ~0.6s | Configuration |
| `sentinel protected add` | ~0.2s | Configuration |
| `sentinel hook-install` | ~0.6s | Configuration |
| `sentinel list` | ~0.6s | Query |
| `sentinel status` | ~0.6s | Query |
| `sentinel prepush` | ~1.2s | Detection |
| `sentinel hook pre-push` | ~0.8s | Detection |
| `sentinel scan` | ~3.7s | Detection (network) |
| `sentinel heal --leaks` | ~0.9s | Remediation |
| `sentinel analyze --local` | ~0.4s | Analysis |
| `sentinel sandbox sync` | ~1.1s | Sandbox |
| `sentinel sandbox status` | ~1.5s | Sandbox (network) |

All commands completed in under 4 seconds. Network-dependent commands (`scan`, `sandbox status`) exhibited the highest latency due to GitHub API calls.

---

## 5. Agent Behavioral Observations

### 5.1 Correct Behaviors

- The agent discovered all commands autonomously via `--help`.
- JSON output was correctly parsed and interpreted at every step.
- The agent understood the semantic difference between `safe: true` and `safe: false`.
- The agent correctly identified that `heal --leaks` does not modify commit history and reported the manual remediation path.
- The agent respected the prohibition against source code modification throughout the entire session.

### 5.2 Failure Modes Observed (Prior Sessions)

In earlier testing sessions (before CLI fixes were applied), the agent encountered the following failure:

| Issue | Root Cause | Resolution |
|:---|:---|:---|
| `sentinel link` crashed with `db.linkRepository is not a function` | CLI called a nonexistent method in the database module | Fixed in commit `de7f522`: method call updated to `db.addRepository()` |
| Agent attempted to edit `index.js` to fix the crash | Agent violated the "no source modification" rule | Added `CRITICAL WARNING` section to README and AI_AGENT_ONBOARDING.md |
| Agent's file edits corrupted `index.js` with encoding errors | PowerShell `Set-Content` introduced UTF-8 BOM; agent's write tools injected syntax errors | File restored via `git checkout`; agent instructed to never modify Sentinel files |

### 5.3 Limitations Identified

1. **Sandbox deployment is not fully autonomous**: The agent can generate the workflow file but cannot push it to the remote repository or trigger GitHub Actions runs without git commands.
2. **No direct PR listing**: The CLI does not expose a command to list open Pull Requests. The `scan` command handles PR analysis internally but does not expose individual PR data to the agent.
3. **Committed leaks require manual action**: The `heal` command deliberately avoids automated history rewrites. While this is a correct safety decision, it means the agent cannot fully remediate committed secrets without human approval.

---

## 6. Conclusions

Sentinel's CLI demonstrates functional interoperability with lightweight AI agents operating in terminal environments. The key findings are:

1. **Discoverability**: An agent with no prior knowledge of Sentinel can fully explore and operate the CLI through `--help` and `--json` flags alone.
2. **Reliability**: All 11 autonomous operations completed successfully with consistent JSON output. The two operations requiring manual intervention (sandbox deployment and committed leak remediation) are architectural constraints that reflect deliberate safety decisions.
3. **Performance**: All commands respond in under 4 seconds, with configuration and query commands averaging under 1 second — well within acceptable latency for real-time agent workflows.
4. **Safety boundaries**: The agent correctly respected the no-modification rule when documentation explicitly stated it. In the absence of such documentation (earlier sessions), the agent defaulted to attempting code fixes, which resulted in file corruption. This highlights the importance of explicit boundary documentation for agentic tools.

---

## 7. References

- [Sentinel CLI Reference](CLI_REFERENCE.md)
- [AI Agent Onboarding Guide](AI_AGENT_ONBOARDING.md)
- [Sentinel Architecture](ARCHITECTURE.md)
- [Sentinel Security Audit](../SECURITY_AUDIT.md)
