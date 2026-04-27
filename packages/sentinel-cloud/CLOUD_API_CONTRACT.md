# Sentinel Cloud API Contract (v1.0)
**Component:** Intelligence Bridge API
**Architecture Phase:** V3

## Endpoint: `/api/v1/intelligence/ingest`
**Method:** `POST`
**Purpose:** Receives anonymized threat events from the `sentinel-cli` and queues them for validation, sanitization, and database storage.
**Security:** Requires Bearer JWT.

---

## 1. Request Payload (Schema)

The payload structure strictly prohibits raw source code at the `FREE` tier. 

```json
{
  "meta": {
    "timestamp": "2026-04-25T16:00:00Z",
    "cli_version": "3.0.0",
    "repo_hash": "sha256_hash_of_repo_url",
    "language": "javascript",
    "tier": "FREE"
  },
  "threat": {
    "category": "supply_chain",
    "pattern": "obfuscated_install_script",
    "risk_score": 0.92,
    "confidence": 0.87
  },
  "metrics": {
    "scan_time_ms": 420,
    "files_scanned": 182
  },
  "ast_features": {
    "uses_eval": true,
    "dynamic_require": true,
    "entropy": 4.7
  }
}
```
*Note: `ast_features` is populated only for PRO/ENTERPRISE tiers or users who opted into Level 2 data sharing.*

---

## 2. Supabase Database Schema

Supabase is used purely for metadata, analytics, and user states. Heavy payloads (if Enterprise opts in) are redirected to AWS S3.

### Table: `intelligence_events`
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key -> Auth)
- `repo_hash` (VARCHAR, Indexed for deduplication)
- `event_hash` (VARCHAR, UNIQUE)
- `category` (VARCHAR, e.g., 'supply_chain')
- `pattern` (VARCHAR, e.g., 'obfuscated_install_script')
- `risk_score` (FLOAT)
- `confidence` (FLOAT)
- `timestamp` (TIMESTAMPTZ)

### Table: `event_metrics`
- `event_id` (UUID, Foreign Key -> intelligence_events)
- `scan_time_ms` (INT)
- `files_scanned` (INT)

### Table: `event_features` (PRO Tier)
- `event_id` (UUID)
- `entropy` (FLOAT)
- `uses_eval` (BOOLEAN)
- `dynamic_require` (BOOLEAN)

---

## 3. Internal Processing Pipeline

Before data is written to Supabase, the Node.js API executes the following pipeline:
1. **Validate:** Check JWT token, parse JSON against strict Joi/Zod schema. Return 400 on invalid payload.
2. **Rate Limit:** Redis-backed rate limiting (e.g., 100 requests/day for FREE). Return 429 if exceeded.
3. **Sanitize:** Strip any string length > 50 in `pattern` to prevent accidental payload injection. Verify no file paths exist in the data.
4. **Dedupe:** Generate a hash of `(user_id + repo_hash + category)`. If an identical alert was sent in the last 24h, drop it to prevent spam.
5. **Store:** Insert into `intelligence_events`.
