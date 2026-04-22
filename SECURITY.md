# Security Policy

# Security & Breaches Policy (VDP)

As an Enterprise Auditable Governance Engine, Sentinel is designed to protect CI/CD environments. We take the robustness of our Adaptive AST and Offline Validations very seriously.

## Supported Versions

The following Rulepacks and Engine Versions are actively supported for threat protection:

| Component        | Version Focus    | Supported          |
| ---------------- | ---------------- | ------------------ |
| Sentinel Engine  | 3.6.x (Unified)  | Yes                |
| Governance Rules | Rulepack 2026.04+| Yes                |
| UI Validations   | Strict Zod Gen.  | Yes                |
| Legacy (v2.x)    | None             | No                 |

## Reporting a Breach or Heuristic Bypass

**Please do not report security bypasses, evasion payloads, or core vulnerabilities through public GitHub issues.**

If you discover a way to bypass our Zero-False-Negative regression suites, or identify an exploit vector against the React Local Replay System itself, please disclose it responsibly:

1. **GitHub Security Advisories:** Navigate to the "Security" tab of this repository on GitHub and select "Report a vulnerability". Maintain the payloads in private channels to prevent 0-day abuse.
2. **Evasion Payload Requirements:** When submitting a heuristic bypass, please provide:
   - The malicious payload sample.
   - The expected `SARB-` Rule ID that should have captured it.
   - A demonstration of how it evades the trigger boundaries of the orchestrator.

### Our Commitment SLA

- We will acknowledge receipt of your disclosure within **48 hours**.
- We will construct an isolation `benchmark_suite.js` test case within **5 business days** to deterministically assert the block.
- Once fixed under the new Release Rulepack, we will provide credit for the discovery (unless anonymity is requested).

---

## Security Audit History

For transparency, Sentinel maintains a public log of its internal security audits. Our UI strictly enforces offline rendering, guaranteeing a localized air-gap. Consult architecture decisions at [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).
