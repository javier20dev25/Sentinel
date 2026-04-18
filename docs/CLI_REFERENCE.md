# Sentinel CLI Reference (`sntl`)

The `sntl` command-line interface provides developers with a streamlined way to manage and scan repositories within their terminal or CI workflow.

## 🚀 Setup

To use the `sentinel` command globally, ensure you are in the project root and run:
```bash
npm link
```
Alternatively, use it directly via `node src/ui/cli/index.js`.

---

## 🛠️ Essential Commands

### `sentinel prepush` [NEW]
**The primary security gate.** Analyzes outbound commits before pushing.
- **Advisory Mode**: Does NOT block the push. Provides a detailed security report and disclaimer.
- **Detection**: Catch both staged changes and commits that haven't been pushed to upstream yet.
- **Options**:
    - `--json`: Structured output for AI agents and CI/CD pipelines.

### `sentinel heal` [NEW]
Automated incident response to contain leaks or threats.
- **`--leaks`**: Automatically removes protected files from outbound commits. Handles both staged files (`git reset`) and already-committed files (`git reset HEAD~1 --soft` + re-commit) without losing other staged work.
- **`--threats`**: Unstages detected threats and moves them to `.sentinel/quarantine/` for analysis.

### `sentinel protected` [NEW]
Manage sensitive folders and files for the current repository.
- **`add <path>`**: Add a directory or file to the protected list.
- **`list`**: View all protected paths for the linked repo.
- **`remove <id>`**: Remove a path from protection using its ID.

### `sentinel hook-install` [NEW]
Installs the **Sentinel Security Skill** (Git Hook) in the current repository.
- **Idempotent**: Safe to run multiple times; it won't duplicate hook entries.
- **Function**: Automatically triggers an advisory scan during `git push`.

---

## 🛠️ Management Commands

### `sentinel link <local_path> <github_full_name>`
Link a local repository to the Sentinel database.
- **`<local_path>`**: Path to the project root.
- **`<github_full_name>`**: repository name in `owner/repo` format.
- **Example**: `sentinel link . javier20dev25/my-app`

### `sentinel list`
Display all repositories currently monitored by Sentinel.
- Shows: ID, Name, Last Scan, and Status (SAFE/INFECTED).

### `sentinel status`
Show high-level security status of all linked repositories in a clean table.

### `sentinel scan`
Trigger an immediate scan of **all** linked repositories.
- Scans local files and remote PRs (if configured).

### `sentinel hook <event>`
Internal entrypoint for Git hooks.
- **`pre-push`**: Executes the advisory analysis. Always exits with status 0 to prevent breaking Git workflows on Windows.

---

## 🔬 Sandbox & Remote (Sentinel 3.0)

### `sentinel sandbox [command]`
Management of dynamic analysis in isolated environments.
- **`generate`**: Get the `sentinel-sandbox.yml` template.
- **`trigger <repo>`**: Dispatches a remote analysis run.
- **`status <repo> <runId>`**: Check execution state.

---

## ⚙️ Logic & Normalization
Sentinel uses **Cross-Platform Path Normalization**. All paths are normalized to lowercase with forward slashes (`/`), ensuring consistent protection between Windows and Unix environments.

**AI Support**: Use the `--json` flag on any command for machine-readable output.
