# Sentinel API Reference (v1.0)

Sentinel's backend server (Express) runs locally on **Port 3001**. This API manages the core security logic, authentication, and database interaction.

## 🔑 Authentication
The API is protected by **JWT (JSON Web Tokens)**.

1. **Setup**: `/api/auth/local/setup` (POST) sets the Master Password hash.
2. **Login**: `/api/auth/local/login` (POST) returns a signed JWT.
3. **Usage**: Include `Authorization: Bearer <token>` in the headers of all subsequent requests.

---

## 📡 API Endpoints

### System & Health
- **`GET /api/system/check`**: Verifies if `git` and `gh` (GitHub CLI) are installed.
- **`GET /api/system/stats`**: Real-time telemetry (RAM, CPU, Uptime).
- **`POST /api/system/shutdown`**: Gracefully terminates the backend process.

### Repositories
- **`GET /api/repositories`**: Returns all tracked repositories and their calculated security score (0-100).
- **`POST /api/repositories/:id/scan`**: Triggers a deep scan (Local + PRs) and streams progress via SSE.

### Security Shield (SPS)
- **`POST /api/shield/harden`**: Applies project-specific security hardening.
- **`POST /api/shield/safe-install`**: Wraps `npm install` with a pre-scan layer.
- **`GET /api/shield/structure/:repoId`**: Returns the interactive filesystem tree.

### 🛡️ Asset Guard (SAG)
- **`GET /api/git/staged`**: Scans and returns files staged in Git (`git diff --cached`).
- **`POST /api/git/push`**: Performs the final Asset Guard security check before calling `git push`.

---

## 🌊 Live Updates (SSE)
Client applications can subscribe to real-time events via:
`GET /api/ui/stream`

### Event Types:
- `scan-log`: Real-time status update from the scanner.
- `shield-log`: Hardening progress logs.
- `ui-intent`: Remote navigation command from the CLI.

---

## 🔒 Security Policy
The Sentinel API adheres to the following:
1. **Argument Array Execution**: Prevents shell injection by using `execFileSync` instead of `exec`.
2. **CORS Hardening**: Strict origin headers to prevent malicious websites from interacting with your local security server.
3. **Input Sanitization**: All repository names and paths are validated against a strict whitelist.
