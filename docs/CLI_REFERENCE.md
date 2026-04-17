# Sentinel CLI Reference (`sntl`)

The `sntl` command-line interface provides developers with a streamlined way to manage and scan repositories within their terminal or CI workflow.

## 🚀 Setup

To use the `sentinel` command globally, ensure you are in the project root and run:
```bash
npm link
```
Alternatively, use it directly via `node src/ui/cli/index.js`.

---

## 🛠️ Commands

### `sntl link <local_path> <github_full_name>`
Link a local repository to the Sentinel database.
- **`<local_path>`**: Absolute or relative path to the project root.
- **`<github_full_name>`**: repository name in `owner/repo` format.
- **Example**: `sntl link ./my-app javier20dev25/my-app`

### `sntl list`
Display all repositories currently monitored by Sentinel.
- Shows: ID, Repository Name, Last Scan, and Current Status (SAFE/INFECTED).

### `sentinel scan`
Trigger an immediate, headless scan of **all** linked repositories.
- Scans both local files and remote Pull Requests.
- Sends system notifications if threats are found.

### `sentinel hook <event>`
Sentinel Git Hook Entrypoint for real-time traffic/push analysis.
- **`<event>`**: The Git hook event (currently supports `pre-push`).
- **Options**:
    - `--reverse`: Dry-run mode. Analyzes code but does not block the push; provides remediation steps instead.
- **Example**: `sentinel hook pre-push`

### `sntl open`
Remotely control the Sentinel Desktop UI from the terminal.
- **Options**:
    - `--repo <name>`: Open the dashboard and navigate to a specific repository.
    - `--pr <url>`: Open the security view for a specific PR URL.
    - `--scan-all`: Trigger a global scan and open the UI immediately.

### `sntl sandbox [command]` (Sentinel 3.0)
Management of dynamic analysis in isolated environments (GitHub Actions).

- **`generate`**: Displays the `sentinel-sandbox.yml` template for manual setup.
- **`trigger <repo> [branch]`**: Dispatches an analysis run.
    - `--async`: Dispatches the run and returns the Run ID immediately.
- **`status <repo> <runId>`**: Queries current execution state.
- **`analyze <repo> <runId>`**: Downloads and evaluates telemetry signals.

#### Example: Successful Analysis (`sntl sandbox trigger owner/repo --wait`)
```text
🚀 Triggering sandbox analysis for owner/repo on branch main...
✅ Run triggered! ID: 12345678
🔗 URL: https://github.com/owner/repo/actions/runs/12345678
⏳ Waiting for analysis to complete (this may take a few minutes)...
   [STATUS] in_progress
   [STATUS] completed (success)
✅ Analysis completed successfully. Fetching results...
📥 Downloading artifacts for run #12345678...
🔍 Analyzing telemetry...

✅ [SAFE] No malicious behavior detected in sandbox simulation.
```

#### Example: Threat Detected (`sntl sandbox trigger owner/repo --wait`)
```text
🚀 Triggering sandbox analysis for owner/repo on branch main...
✅ Run triggered! ID: 87654321
🔗 URL: https://github.com/owner/repo/actions/runs/87654321
⏳ Waiting for analysis to complete (this may take a few minutes)...
   [STATUS] in_progress
   [STATUS] completed (success)
✅ Analysis completed successfully. Fetching results...
📥 Downloading artifacts for run #87654321...
🔍 Analyzing telemetry...

🚨 FOUND 1 SUSPICIOUS BEHAVIORS IN SANDBOX:

[HIGH] UNEXPECTED_NETWORK_CONNECTIONS
Message: [SANDBOX] 1 conexión(es) de red nuevas detectadas durante npm install en owner/repo.
Evidence: > tcp 45.33.22.11:443 [ESTABLISHED]...

Risk Score: 3.0/10
```

---

## ⚙️ Configuration
Sentinel's CLI shares the same SQLite database as the Desktop application. Changes made in the terminal are reflected in the UI in real-time.
