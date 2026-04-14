# 🛡️ Sentinel: AI Agent Integration Guide

Welcome, Agent. This guide is designed to help you integrate Sentinel's security intelligence into your workflow. Whether you are running inside an IDE (Cursor, Windsurf) or as a standalone CI agent, Sentinel provides the tools to ensure your human's code is safe.

## 1. Programmatic Interface (CLI)

Sentinel's CLI is built for agentic consumption. Use the global `--json` flag to suppress human-focused emojis and logs, receiving strictly machine-readable data on `stdout`.

### Global Protocol
- **JSON Mode**: Always append `--json`.
- **Stdout**: Reserved for the JSON result.
- **Stderr**: Used for informational logs and debugging info.
- **Exit Codes**:
    - `0`: **SAFE** / Operation Successful.
    - `1`: **THREAT DETECTED** / Security risk identified.
    - `2`: **ERROR** / System failure or API timeout.

### The "Security Briefing" (Context Optimized)
Agents have limited context windows. Use the `briefing` command to get a token-optimized summary (<350 tokens).

```bash
sentinel briefing --target owner/repo --format markdown
```

**Recommended Flow for Agents:**
1. Call `sentinel briefing`.
2. If `score < 80`, inform the human: *"Sentinel suggests this repo has security debt (Score: X). Should I apply hardening?"*
3. If approved, run `sentinel repo-harden --target owner/repo --apply`.

---

## 2. API Sidecar (Local HTTP)

If you are a web-based agent or running a sidecar process, you can reach Sentinel at `http://localhost:3001`.

### Endpoints
- `GET /api/briefing/:repoId`: Get status by internal ID.
- `GET /api/briefing/name/:owner/:repo`: Get status by GitHub name.
- `GET /api/system/check`: Verify Sentinel's health and toolchain.

---

## 3. Recommended Prompts for Your System Prompt

If you want to integrate Sentinel deeply, add these instructions to your system prompt:

> "I have access to Sentinel, a security sidecar. Before suggesting a merge or running unknown scripts, I should run `sentinel scan` or `sentinel briefing`. If Sentinel returns an exit code of 1, I must pause and warn the user about specific threat rules triggered."

---

## 4. Automated Hardening
You can programmatically protect a repository by calling:
```bash
sentinel repo-harden --target <repo> --apply
```
*Note: This command may require a one-time manual 'YES' confirmation from the human via the terminal unless overridden by environment variables.*

---
*Sentinel 3.5: Making the era of AI Agents safer, one repo at a time.*
