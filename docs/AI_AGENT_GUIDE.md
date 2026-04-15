# 🤖 Sentinel: AI Agent Integration Guide (v3.6)

> This guide is addressed directly to AI agents and language models. Sentinel is designed as a **security-aware co-pilot** for developers, and it exposes a complete machine-readable interface for autonomous use.

---

## Quick Reference for Agents

| Task | Command | Output |
| :--- | :--- | :--- |
| Check repo security score | `sentinel briefing --target owner/repo --json` | JSON with score, alerts, CVSS |
| Run a full dependency scan | `sentinel scan --target ./path --json` | JSON list of findings |
| Check for secrets/API keys | `sentinel scan --secrets --target ./path --json` | JSON with matched patterns |
| Harden environment | `sentinel repo-harden --target owner/repo --apply` | JSON confirmation |
| Get repo link status | `sentinel list --json` | JSON array of repos |
| Link a new repo | `sentinel link --repo owner/repo` | JSON confirmation |
| Unlink a repo | `sentinel unlink --repo owner/repo` | JSON confirmation |
| System health check | `sentinel system-check --json` | JSON with toolchain status |

---

## 1. Protocol & Exit Codes

All CLI commands accept `--json` to suppress human-readable decorations and return **strict JSON on stdout**.

```bash
sentinel scan --target ./my-project --json
```

### Exit Code Contract

| Code | Meaning | Agent Action |
| :---: | :--- | :--- |
| `0` | ✅ Safe / Success | Continue normally |
| `1` | 🚨 Threat Detected | Pause — alert the user with details |
| `2` | ⚠️ System Error | Log error, retry once, then escalate to user |

### Stream Channels

- **`stdout`** — Machine-readable JSON result only
- **`stderr`** — Human-facing logs, progress, emojis (safe to pipe to `/dev/null`)

---

## 2. Core CLI Commands & JSON Output Schemas

### `sentinel scan` — Static + Behavioral Analysis

Scans a local path for malware patterns, AST anomalies, secrets, and lockfile integrity.

```bash
sentinel scan --target ./project --json
```

**Output schema:**
```json
{
  "status": "THREAT_DETECTED",
  "score": 8.5,
  "duration_ms": 1203,
  "findings": [
    {
      "rule_id": "MALWARE_EVAL_OBFUSCATION",
      "severity": "HIGH",
      "file": "node_modules/evil-pkg/lib/index.js",
      "line": 42,
      "evidence": "eval(String.fromCharCode(114,109,32,45,114,102,32,47))",
      "description": "Detected obfuscated eval payload (charCode chain)",
      "recommended_action": "Remove dependency and audit lockfile"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "moderate": 2,
    "low": 0
  }
}
```

---

### `sentinel briefing` — Token-Optimized Security Summary

Designed for agents with limited context windows. Returns a concise (<400 tokens) security status.

```bash
sentinel briefing --target owner/repo --json
```

**Output schema:**
```json
{
  "repo": "owner/repo",
  "score": 72,
  "rating": "CAUTION",
  "top_threats": [
    "LOCKFILE_MISMATCH",
    "VULNERABLE_DEP: axios < 1.8.2"
  ],
  "recommendation": "Upgrade axios. Regenerate lockfile from main branch.",
  "last_scan": "2026-04-14T18:56:00Z"
}
```

**Score Interpretation:**

| Score | Rating | Recommended Agent Action |
| :--- | :--- | :--- |
| 90–100 | ✅ SAFE | No action required |
| 70–89 | ⚠️ CAUTION | Inform user, await approval to patch |
| 50–69 | 🟠 AT_RISK | Recommend hardening, ask for confirmation |
| 0–49 | 🚨 CRITICAL | Block merge/push, force user review |

---

### `sentinel system-check` — Toolchain Health

Verify all Sentinel subsystems before running automated workflows.

```bash
sentinel system-check --json
```

**Output schema:**
```json
{
  "status": "READY",
  "node_version": "22.3.0",
  "git_available": true,
  "gh_cli_authenticated": true,
  "database": "OK",
  "sandbox_enabled": true,
  "api_reachable": true,
  "warnings": []
}
```

---

## 3. API Sidecar (Local HTTP)

If Sentinel's backend is running (`npm start` in `packages/api`), it exposes a REST API at **`http://localhost:3001`**.

### Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/briefing/:repoId` | Security briefing by internal DB ID |
| `GET` | `/api/briefing/name/:owner/:repo` | Security briefing by GitHub slug |
| `GET` | `/api/scan/:repoId` | Latest scan results for a repo |
| `GET` | `/api/system/check` | Sentinel health status |
| `POST` | `/api/scan/trigger` | Trigger a new scan (body: `{ repoId }`) |
| `GET` | `/api/repositories` | List all linked repositories |

### Example Fetch (for web agents)
```javascript
const res = await fetch('http://localhost:3001/api/briefing/name/torvalds/linux');
const data = await res.json();
if (data.score < 70) {
  console.warn('Security risk detected:', data.top_threats);
}
```

---

## 4. Recommended System Prompt Integration

Add this to your agent's system prompt to enable automatic security checks:

```
I have access to Sentinel, a local security sidecar (CLI: `sentinel`, API: localhost:3001).

Rules:
- Before approving any PR merge or running any npm install, run `sentinel scan --target ./path --json`.
- If the exit code is 1 (THREAT_DETECTED), I MUST stop and show the user the specific `findings` array.
- If score < 70, I MUST warn the user before proceeding with any dependency changes.
- I may run `sentinel briefing` at the start of every session to give the user a passive security update.
- I must NEVER run `sentinel repo-harden --apply` without explicit user confirmation.
```

---

## 5. Autonomous Hardening Workflow

For CI/CD agents or automated pipelines that have explicit permission to apply patches:

```bash
# Step 1: Assess risk
SCORE=$(sentinel briefing --target owner/repo --json | node -e "process.stdin.resume();let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d).score))")

# Step 2: Conditionally harden
if [ "$SCORE" -lt 70 ]; then
  sentinel repo-harden --target owner/repo --apply
fi
```

> [!CAUTION]
> The `--apply` flag executes real changes on the local system. Always gate this behind human confirmation in interactive workflows.

---

## 6. What Sentinel Can and Cannot Do

| ✅ Can Do | ❌ Cannot Do |
| :--- | :--- |
| Detect obfuscated malware in `node_modules` | Access the internet autonomously |
| Identify lockfile poisoning | Modify files outside the project root |
| Monitor subprocess behavior in CI Sandbox | Execute AI-generated code without user approval |
| Scan secrets in staged Git commits | Connect to external telemetry services |
| Trigger GitHub webhooks for PR analysis | Bypass the "Human-in-the-Loop" for destructive actions |

---

*Sentinel 3.6 — Building the era of AI-assisted development securely, one scan at a time.*
