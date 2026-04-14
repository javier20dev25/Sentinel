# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6.0] - 2026-04-14

### Added
- **Intelligence Categorization**: Alerts now include detailed classification (`STATIC`, `DYNAMIC`) and subcategories (`SECRETS`, `MALWARE`, `SUPPLY_CHAIN`, `VULNERABILITIES`).
- **Sentinel Smart Webhooks**: New ingestion engine to receive real-time events from GitHub, enabling instant scans on PR and Push events without polling.
- **Enhanced Threat UI**: Added visual badges in the Threat Log to display threat categories and subcategories.
- **Security Audit Documentation**: Internal security research and audit report (`SECURITY_AUDIT.md`).
- **Official License**: MIT License added to the repository.

### Changed
- **Polling Optimization**: Refined the background polling service to work in tandem with the new webhook engine.
- **CLI Intelligence**: Updated the `scan` command to report categorized findings in the terminal.
- **UI Aesthetics**: Improved the rendering of threat details with indigo-themed intelligence badges.

### Security
- **Webhook Validation**: Implemented `crypto.timingSafeEqual` for HMAC signature verification to prevent timing attacks.
- **Sandbox Hardening**: Improved telemetry analysis in the CI Sandbox for more accurate detection of malicious network activity.

---

## [3.0.0] - 2026-03-20

### Added
- **CI Sandbox Orchestrator**: Dynamic behavior analysis using GitHub Actions.
- **Sentinel Project Shield**: Automated environment hardening for repos.
- **Electron UI**: Professional dark-mode dashboard for monitoring multiple repositories.
- **AI Logic Core**: Integration with LLMs to explain threats and suggest remediation commands.

---

## [1.0.0] - 2026-01-10

### Added
- Initial release of Sentinel CLI and core static analysis engine.
- SQLite backend for local persistence.
