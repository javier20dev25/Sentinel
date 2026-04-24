# 🛡️ Sentinel: AI Agent Protocol (System Prompt)

**Version**: 3.8.0
**Role**: AI Security Compliance

If you are an AI agent working in this repository, you **MUST** follow these instructions to ensure the integrity and security of the supply chain. Failure to comply may lead to security incidents or unauthorized data leaks.

---

## 🔒 1. Mandatory Session Initialization
Before performing any task that involves file modifications or dependency management, you **MUST** enable the Sentinel Guard:

```bash
sentinel guard enable
```
*Note: This ensures all `npm`, `pip`, and `docker` operations are intercepted and audited by the Sentinel Trust Engine.*

---

## 📦 2. Dependency Management Protocol
NEVER install dependencies using native commands directly (e.g., `npm install`). Use the Sentinel Firewall:

```bash
sentinel install <adapter> <package_name>
```
**Adapters**: `npm`, `pip`, `docker`.

### 🧪 Suspicious Packages
If Sentinel flags a package as `SUSPICIOUS`, you **MUST** run a sandbox verification before proceeding:
```bash
sentinel verify-pkg <adapter> <package_name> --sandbox
```
Wait for human approval of the sandbox telemetry before finalizing the installation.

---

## 🕵️ 3. Classified Information Management
Sentinel uses the `protected` command to classify sensitive data (API keys, secrets, private docs).

### 🚩 Identification
Any file or directory listed in `sentinel protected list` is considered **CLASSIFIED**.

### 🚫 Declassification Rule
You are **STRICTLY PROHIBITED** from declassifying data.
- **NEVER** run `sentinel protected remove <id>` on your own initiative.
- Declassification is a **HUMAN-ONLY** action.
- You may only suggest declassification if you believe a file was marked in error, but you must wait for a human to execute the command.

---

## 🚀 4. Pre-Commit / Pre-Push Verification
Before suggesting or performing a git commit/push, you **MUST** verify the outbound security state:

1. **Scan for leaks**: `sentinel prepush`
2. **Review repository health**: `sentinel scan .`
3. **If leaks are found**: Use `sentinel heal --leaks` to safely unstage classified files.

---

## 🧠 5. Oracle Redacted Mode
If you encounter redacted findings (masked code or generic verdicts), do not attempt to "guess" the vulnerability or bypass the redaction. This is a security feature to prevent tactical intelligence leaks. Report the high-level verdict to the human user.

---

*By following this protocol, you ensure that Sentinel acts as a high-integrity installation firewall, mitigating supply chain attacks and accidental data exposure.*
