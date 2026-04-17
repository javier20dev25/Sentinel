# Sentinel Deployment Specifications

Sentinel is offered in three primary formats to support different environments and security requirements.

---

## 🏗️ 1. Windows Installer (Standard Edition)
The recommended option for standard Windows users.

- **Technology**: Built using `electron-builder`.
- **System Requirements**: 
    - Windows 10/11 x64.
    - 4GB RAM minimum (8GB recommended).
- **Security Check**: Sentinel Installer creates a unique application signature for the environment.
- **Paths**:
    - AppData: `%LOCALAPPDATA%\Programs\sentinel`
    - Data: `%APPDATA%\sentinel\data`

---

## 📦 2. Portable Edition (Zero Installation)
Ideal for security researchers and portable lab environments.

- **Distribution**: `.zip` package.
- **Workflow**: Extract the contents to any directory and run `Sentinel.exe`.
- **Data Persistence**: All security logs and database entries are stored in a `data` subfolder *inside* the extracted directory, keeping the host system clean.

---

## ⚡ 3. Web Edition (Developer/Power User)
The most powerful and feature-complete version of Sentinel. Runs directly from source.

### Setup Requirements:
- **Node.js**: 20.x or 22.x LTS (required for `better-sqlite3` prebuilt binaries).
- **Package Manager**: npm or yarn.
- **GitHub CLI (`gh`)**: Authenticated with `gh auth login`.

### Quick Launch Command:
```bash
npm run sentinel
```

### Features exclusive to the Web Edition:
- **Sentinel Project Shield (SPS)**: Real-time hardening of the underlying Node.js environment.
- **Hot-Reloading UI**: Developers can modify the security dashboard and see changes instantly.
- **CLI Linkage**: Enables global use of the `sntl` command.

---

## ⚖️ Edition Comparison

| Feature | Standard (EXE) | Portable | Web Edition |
| :--- | :---: | :---: | :---: |
| UI Interface | ✅ | ✅ | ✅ |
| CLI Access | ❌ | ❌ | ✅ |
| Project Hardening (SPS) | ❌ | ❌ | ✅ |
| Asset Guard (SAG) | ✅ | ✅ | ✅ |
| Remote Shutdown | ✅ | ✅ | ✅ |
| Zero System Impact | ❌ | ✅ | ❌ |
| Source Auditable | ❌ | ❌ | ✅ |
| Best Performance | ✅ | ✅ | ✅ |
| Prebuilt Binaries | ✅ | ✅ | ❌ |
