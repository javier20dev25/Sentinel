# Sentinel Pro — Feature Specification (Internal Draft)

> **Status:** Pre-launch planning. This document is for internal use only.
> **Version Target:** v4.0.0-pro
> **Based on:** Sentinel Free v3.6.x

---

## 🎯 Mission

Sentinel Pro is the commercial evolution of Sentinel Free. While the Free version provides robust local security monitoring, Pro targets **development teams, enterprises, and security-conscious organizations** that need:

- **Multi-repository coverage** (unlimited repos vs. Free's limited set)
- **Cloud-synced dashboards** across multiple machines
- **Priority threat intelligence feeds**
- **API-first architecture** for deep CI/CD integration
- **Professional support and SLA**

---

## 🔐 License & Activation System (Planned)

### License Model
- **License Key**: A unique `SNTL-PRO-XXXX-XXXX-XXXX-XXXX` key purchased by the user.
- **Activation**: The `sentinel activate <license-key>` CLI command contacts the Sentinel licensing server to validate and store the key locally.
- **Offline Grace Period**: 14 days without internet connectivity before re-validation required.
- **Deactivation**: `sentinel deactivate` frees the key for use on another machine (max 2 simultaneous devices).

### License Storage
```
~/.sentinel/license.json  (encrypted with machine fingerprint)
```

---

## 💎 Pro-Exclusive Features

### 1. Team Dashboard (Cloud Sync)
- Sentinel results synced to a private cloud endpoint.
- Web dashboard accessible from `app.sentinel-security.dev` (planned domain).
- Share scan results with team members without exposing raw files.

### 2. Real-Time GitHub PR Guard (Enhanced)
- **Free**: PR analysis on demand.
- **Pro**: Automatic PR analysis as a GitHub App (webhook-triggered, no polling).
- Inline PR comments with severity badges directly from Sentinel.

### 3. Policy-as-Code (Custom Rules Engine)
- Free tier uses built-in YAML rules.
- **Pro**: Define custom detection rules in a `.sentinel/rules/` folder.
- Rules are hot-reloaded without restart.
- Rule marketplace (planned): download community-vetted rules.

### 4. Supply Chain Intelligence Feed
- Free: Static CVE database (updated weekly).
- **Pro**: Live threat feed updated in real-time from Sentinel's curated intelligence network.
- Includes: malicious package registry tracking, npm namespace squatting alerts, typosquatting detection.

### 5. AI Remediation (Autonomous Mode)
- Free: AI suggestions require manual execution (Human-in-the-Loop).
- **Pro**: Configurable "Trust Score" — allow AI to auto-apply low-risk fixes (e.g., `npm update` for patch-level bumps) without manual confirmation.

### 6. Audit Report Export
- **Pro**: Export full audit reports as:
  - PDF (branded, shareable with managers/clients)
  - CSV (for SIEM ingestion)
  - SARIF (for GitHub Code Scanning integration)

### 7. Priority Support
- Discord channel with direct access to the maintainer.
- Bug fix SLA: Critical bugs addressed within 48h (vs. best-effort for Free).

---

## 🗂️ Directory Structure for Pro

```
packages/
  pro/                    ← NEW: Pro-exclusive backend logic
    license/
      validator.js        ← License key validation
      fingerprint.js      ← Machine fingerprint generation
      storage.js          ← Encrypted local license storage
    features/
      cloud-sync.js       ← Dashboard sync (stubbed)
      custom-rules.js     ← Policy-as-Code engine
      threat-feed.js      ← Live intelligence feed client
      report-exporter.js  ← PDF/CSV/SARIF exporter
      pr-guard.js         ← GitHub App webhook handler
    api/
      pro-middleware.js   ← License gate for Pro API routes
```

---

## 🔑 License Gating Strategy

All Pro features are gated by a single middleware check:

```javascript
// packages/pro/api/pro-middleware.js
import { validateLicense } from '../license/validator.js';

export function requirePro(req, res, next) {
  const license = validateLicense();
  if (!license.valid) {
    return res.status(402).json({
      error: 'SENTINEL_PRO_REQUIRED',
      message: 'This feature requires Sentinel Pro.',
      upgrade_url: 'https://sentinel-security.dev/upgrade'
    });
  }
  next();
}
```

---

## 📋 Free vs. Pro Comparison (Marketing Table)

| Feature | Free | Pro |
| :--- | :---: | :---: |
| Local repository scanning | ✅ Unlimited | ✅ Unlimited |
| Static AST analysis | ✅ | ✅ |
| CI Sandbox (GitHub Actions) | ✅ | ✅ |
| CLI & Desktop App | ✅ | ✅ |
| AI Agent integration | ✅ | ✅ |
| Linked repositories | Up to 5 | Unlimited |
| Custom detection rules | ❌ | ✅ |
| Cloud dashboard sync | ❌ | ✅ |
| Live threat intelligence feed | ❌ | ✅ |
| PR Guard (GitHub App) | Manual | Automatic |
| AI Auto-Remediation | Human-in-Loop | Configurable |
| Audit report export (PDF/SARIF) | ❌ | ✅ |
| Priority support | ❌ | ✅ |

---

## 🏁 Next Steps (Ordered by Priority)

- [ ] Set up licensing server endpoint (or use LemonSqueezy/Paddle for key management)
- [ ] Implement `sentinel activate` / `sentinel deactivate` CLI commands
- [ ] Build `packages/pro/license/` module (validator + fingerprinter)
- [ ] Create Pro API middleware (`requirePro`)
- [ ] Stub all Pro features behind the middleware gate
- [ ] Design the upgrade landing page
- [ ] Set pricing and launch Pro tier

---

> *Sentinel Pro pricing TBD. This document will be updated when the commercial strategy is finalized.*
