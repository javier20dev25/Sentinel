# Sentinel v3.6.0 - Intelligence & Optimization Release (Commercial Candidate)

## 🛡️ Secure Your Ecosystem with Professional-Grade Intelligence
We are excited to announce **Sentinel v3.6.0**, a significant milestone that brings granular intelligence and real-time responsiveness to the platform. This release transitions Sentinel from a security monitor into a sophisticated DevSecOps orchestrator.

### 🌟 Key Enhancements

#### 1. Intelligence Categorization (Advanced SAST/DAST)
Threats are no longer just "alerts". They are now intellectually categorized to help you prioritize remediation:
- **STATIC Analysis**: Deep AST inspection to find embedded secrets and malicious code patterns.
- **DYNAMIC Analysis**: Real-time behavioral monitoring via the **CI Sandbox**.
- **Subcategories**: Detailed tagging for **MALWARE**, **SUPPLY_CHAIN** threats, **SECRETS**, and **VULNERABILITIES**.

#### 2. Sentinel Smart Webhooks
Bypass aggressive polling and receive instant security insights. Webhooks enable Sentinel to react the millisecond a Pull Request or Commit is pushed to GitHub.
- **Immediate Response**: Triggers scans automatically on events.
- **Cryptographic Security**: Every payload is verified using HMAC SHA256 signatures with timing-attack protection.

#### 3. Professional Security Audit
Included in this release is the first internal **Security Audit Report** (`SECURITY_AUDIT.md`), detailing the resilience of our architecture against shell injections and supply chain vectors.

---

### 🚀 Setup & Usage Guide

#### How to Enable Smart Webhooks
1. **Configure Secret**: Set the `GITHUB_WEBHOOK_SECRET` environment variable in your local environment.
2. **GitHub Setup**:
   - Go to your Repository Settings > Webhooks > Add Webhook.
   - **Payload URL**: Point to your public Sentinel URL or use a tunnel (e.g., ngrok) to `http://localhost:3001/api/webhooks/github`.
   - **Content type**: `application/json`.
   - **Secret**: Use the same secret you defined in Step 1.
   - **Events**: Select "Pull Requests" and "Pushes".

#### How to Generate Production Builds
Sentinel can be packaged into a standalone installer for easier deployment:
1. Navigate to `src/ui`.
2. Run `npm install`.
3. Execute `npm run electron:build`.
4. Artifacts will be generated in `src/ui/dist-electron` (NSIS Installer and Portable ZIP).

---

### 📜 Licensing & Future
This is the **Sentinel Free Edition**, distributed under the **MIT License**. We are committed to keeping the core security engine open and accessible. 

*Stay tuned for the upcoming **Sentinel Pro** edition, featuring enterprise-grade orchestration and fleet management.*

---
**Full Changelog**: [CHANGELOG.md](https://github.com/javier20dev25/Sentinel/blob/main/CHANGELOG.md)
