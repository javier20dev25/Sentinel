# Sentinel CLI Reference (`sntl`)

The `sntl` command-line interface provides developers with a streamlined way to manage and scan repositories within their terminal or CI workflow.

## 🚀 Setup

To use the `sntl` command globally, ensure you are in the `src/ui` directory and run:
```bash
npm link
```
Alternatively, use it directly via `node src/cli/index.js`.

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

### `sntl scan`
Trigger an immediate, headless scan of **all** linked repositories.
- Scans both local files and remote Pull Requests.
- Sends system notifications if threats are found.

### `sntl open`
Remotely control the Sentinel Desktop UI from the terminal.
- **Options**:
    - `--repo <name>`: Open the dashboard and navigate to a specific repository.
    - `--pr <url>`: Open the security view for a specific PR URL.
    - `--scan-all`: Trigger a global scan and open the UI immediately.
- **Mechanics**: Uses Server-Sent Events (SSE) to send an "Intent" to the running UI. If the UI is closed, `sntl` will attempt to launch it automatically.

---

## ⚙️ Configuration
Sentinel's CLI shares the same SQLite database as the Desktop application, located at `src/ui/backend/data/sentinel.db`. Changes made in the terminal are reflected in the UI in real-time.
