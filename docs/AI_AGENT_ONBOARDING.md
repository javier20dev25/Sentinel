# 🤖 Sentinel: AI Agent Onboarding Guide

Welcome, Agent! This guide is a **suggested workflow** to help you get started with Sentinel quickly and effectively. These steps are not mandatory — think of them as a recommended tutorial to familiarize yourself with how Sentinel works. Once you're comfortable, feel free to use commands in whatever order makes sense for your task.

> **CRITICAL RULE**: You are authorized to **use** Sentinel via CLI commands. You must **NEVER** modify Sentinel's source code files. If a command fails or behaves unexpectedly, report it to your human user instead of attempting a code fix.

---

## 📋 Suggested First-Run Workflow

### Step 1: Check System Status
Start by understanding what Sentinel already knows about.
```bash
sentinel status --json
```
This tells you how many repositories are monitored and their current security state. If the response shows `total: 0`, you'll need to link a repository first.

### Step 2: Link Your Repository
Connect the local project directory to its GitHub counterpart.
```bash
sentinel link "." "owner/repo-name" --json
```
- Replace `owner/repo-name` with the actual GitHub repository (e.g., `javier20dev25/Merx`).
- Use `.` if you're already inside the project directory, or provide the full path.
- Verify with `sentinel list --json` to confirm it was linked.

### Step 3: Protect Sensitive Folders
Mark directories that should never be pushed to GitHub.
```bash
sentinel protected add keys --json
sentinel protected add secrets --json
sentinel protected add .env --json
```
Check what's currently protected:
```bash
sentinel protected list --json
```

### Step 4: Install Security Hook
Set up the automatic pre-push security gate.
```bash
sentinel hook-install --json
```
From now on, every `git push` will be intercepted by Sentinel. If threats are found, the push will be **blocked**. To bypass in emergencies: `SENTINEL_BYPASS=1 git push`.

### Step 5: Run a Security Scan
Scan the repository for threats in open Pull Requests.
```bash
sentinel scan owner/repo-name --json
```
Or scan all linked repos at once:
```bash
sentinel scan --json
```

### Step 6: Pre-Push Verification
Before pushing new code, always verify:
```bash
sentinel prepush --json
```
- If `data.safe` is `true`: You're clear to push.
- If `data.safe` is `false`: Run `sentinel heal --leaks --json` to fix staging issues. For committed leaks, follow the manual instructions provided by the command.

---

## 🔄 Ongoing Maintenance Protocol

Once Sentinel is set up, your day-to-day workflow is simple:

1. **Before every push**: `sentinel prepush --json`
2. **If threats found**: `sentinel heal --leaks --json`
3. **Periodic scans**: `sentinel scan --json`
4. **Check status**: `sentinel status --json`

---

## ⚡ Quick Command Reference

| Command | Purpose | JSON Support |
| :--- | :--- | :---: |
| `sentinel status` | View all repos & their security state | ✅ |
| `sentinel link <path> <repo>` | Connect a local folder to GitHub | ✅ |
| `sentinel list` | List all monitored repositories | ✅ |
| `sentinel protected add <path>` | Mark a folder/file as sensitive | ✅ |
| `sentinel protected list` | View protected paths | ✅ |
| `sentinel hook-install` | Install the pre-push security hook | ✅ |
| `sentinel prepush` | Analyze commits before pushing | ✅ |
| `sentinel heal --leaks` | Safely unstage protected files | ✅ |
| `sentinel scan [repo]` | Scan for threats in PRs | ✅ |
| `sentinel analyze --local` | Analyze the local working directory | ✅ |

---

## 📖 Further Reading

For complete documentation on all features and Sentinel's architecture:
- **[CLI Reference](CLI_REFERENCE.md)** — Full command details
- **[User Guide](USER_GUIDE.md)** — Feature explanations
- **[Sandbox Guide](SANDBOX_GUIDE.md)** — Dynamic analysis with GitHub Actions
- **[Architecture](ARCHITECTURE.md)** — How Sentinel is built

---

*Welcome aboard, Agent. Your human's code is now under your protection. 🛡️*
