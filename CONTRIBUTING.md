# Contribution and Development Guidelines (v1.0)

## 1. Development Environment
Sentinel requires a POSIX-compliant environment or Windows PowerShell with the following dependencies:
- Node.js (v18+)
- Git (v2.30+)
- GitHub CLI (gh) for remote synchronization.

## 2. Code Contribution Standards
- **GPG Signing**: All commits MUST be signed using GPG to provide cryptographic proof of authorship and non-repudiation. This is mandatory for protecting the project's intellectual property.
- All logic must be modular and documented using JSDoc.
- Security-sensitive modules (Compiler, Runtime, Risk Engines) must include automated unit tests.
- PRs that modify the `RiskGraph` schema or the `SyncManager` protocol must be accompanied by updated documentation in `docs/`.

## 3. Mandatory Repository Guard
Sentinel uses its own engine to protect its internal policies and core modules. Before starting development, it is highly recommended to activate the internal guard:

```bash
# Validate internal security policies
sentinel playbook validate .sentinel/policies/internal-security.sentinel

# Run a simulation of the internal guard
sentinel playbook simulate .sentinel/policies/internal-security.sentinel
```

## 4. Submission Process
1. Fork the repository.
2. Create a feature branch (`feat/`) or bugfix branch (`fix/`).
3. Ensure all SARB (Sentinel Automated Repository Benchmark) checks pass locally via the pre-commit hook.
4. Submit a Pull Request.

## 5. Security Responsibility
Contributors must adhere to the [Ethical Usage Guidelines](docs/ETHICAL_USAGE.md). Any identified security vulnerabilities in Sentinel itself should be reported via the private security channel and not through public issues.
