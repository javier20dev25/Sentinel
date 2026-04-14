# SECURITY_AUDIT.md — Dependabot Vulnerability Report
**Project:** Sentinel Security Suite  
**Date:** 2026-04-14  
**Reporter:** Dependabot + Manual Audit  
**Total Alerts:** 39 (2 Critical, 14 High, 15 Moderate, 8 Low)

---

## 🔴 Critical Vulnerabilities

### VULN-C01 — Axios: Unrestricted Cloud Metadata Exfiltration via Header Injection Chain
| Field | Detail |
| :--- | :--- |
| **Package** | `axios` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #3 |
| **Severity** | 🔴 Critical |
| **Type** | Direct Dependency |
| **Description** | An attacker can inject crafted HTTP headers that cause Axios to exfiltrate cloud instance metadata (e.g., AWS/GCP/Azure IMDS endpoints). This is exploitable when Sentinel scans a repository containing a specially crafted URL in code that is then fetched by Axios. |
| **Impact** | Cloud credentials leakage, SSRF leading to internal network access. |
| **Fix** | Upgrade `axios` to `>=1.8.2`. |
| **Status** | 🔧 In Progress (upgrade running) |

### VULN-C02 — Axios: NO_PROXY Hostname Normalization Bypass Leading to SSRF
| Field | Detail |
| :--- | :--- |
| **Package** | `axios` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #36 |
| **Severity** | 🔴 Critical |
| **Type** | Direct Dependency |
| **Description** | The `NO_PROXY` environment variable is improperly parsed. An attacker controlling a URL can bypass proxy restrictions and reach internal services that are meant to be blocked (SSRF). |
| **Impact** | Server-Side Request Forgery — could expose internal APIs, metadata services, or databases. |
| **Fix** | Upgrade `axios` to `>=1.8.2`. |
| **Status** | 🔧 In Progress (upgrade running) |

---

## 🟠 High Vulnerabilities

### VULN-H01 — Vite: `server.fs.deny` Bypassed with URL Queries
| Field | Detail |
| :--- | :--- |
| **Package** | `vite` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #32 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | By appending query strings to URLs (e.g., `?something`), attackers can bypass the `server.fs.deny` file restriction list in Vite's dev server, reading arbitrary files outside the project root. |
| **Impact** | Sensitive file read (.env, private keys, secrets) during development. |
| **Fix** | Upgrade `vite` to `>=6.2.3` / `>=8.0.5`. |
| **Status** | 🔧 In Progress (upgrade running) |

### VULN-H02 — Vite: Arbitrary File Read via Dev Server WebSocket
| Field | Detail |
| :--- | :--- |
| **Package** | `vite` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #31 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | Vite's dev-mode WebSocket server doesn't properly validate file paths requested by clients. A malicious page open in the same browser can use the WebSocket connection to read arbitrary files from the local filesystem. |
| **Impact** | Local file system exfiltration via browser-origin attacks. |
| **Fix** | Upgrade `vite` to `>=8.0.5`. |
| **Status** | 🔧 In Progress |

### VULN-H03 — Vite: Path Traversal in Optimized Deps `.map` Handling
| Field | Detail |
| :--- | :--- |
| **Package** | `vite` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #33 |
| **Severity** | 🟠 High (2 instances) |
| **Type** | Direct Dependency (Dev) |
| **Description** | A path traversal vulnerability in how Vite serves `.map` files for optimized dependencies allows reading files outside the intended directory. |
| **Fix** | Upgrade `vite` to `>=8.0.5`. |
| **Status** | 🔧 In Progress |

### VULN-H04 — Electron: Use-After-Free in Offscreen Child Window Paint Callback
| Field | Detail |
| :--- | :--- |
| **Package** | `electron` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #24 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | A use-after-free vulnerability in Electron's offscreen rendering paint callback can be exploited for memory corruption, potentially allowing code execution in the browser process. |
| **Fix** | Upgrade `electron` to `>=36.2.0` or apply a patch release. |
| **Status** | 📋 Pending — requires testing native module rebuild |

### VULN-H05 — Electron: WebContents Fullscreen/Pointer/Keyboard Lock Permission UAF
| Field | Detail |
| :--- | :--- |
| **Package** | `electron` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #21 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | Use-after-free in permission request callbacks for fullscreen, pointer lock, and keyboard lock. Could allow a renderer process to corrupt memory in the main process. |
| **Fix** | Upgrade `electron`. |
| **Status** | 📋 Pending |

### VULN-H06 — Electron: PowerMonitor Use-After-Free (Windows & macOS)
| Field | Detail |
| :--- | :--- |
| **Package** | `electron` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #20 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | Use-after-free vulnerability in the PowerMonitor module affecting Windows and macOS. |
| **Fix** | Upgrade `electron`. |
| **Status** | 📋 Pending |

### VULN-H07 — Electron: Renderer CLI Switch Injection via `commandLineSwitches`
| Field | Detail |
| :--- | :--- |
| **Package** | `electron` |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #19 |
| **Severity** | 🟠 High |
| **Type** | Direct Dependency (Dev) |
| **Description** | The undocumented `commandLineSwitches` webPreference allows injecting arbitrary Chromium CLI arguments into renderer processes, bypassing security controls. |
| **Fix** | Upgrade `electron` and auditing webPreferences in `main.js`. |
| **Status** | 📋 Pending |

### VULN-H08 — node-tar: Arbitrary File Create/Overwrite via Hardlink Path Traversal
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` (node-tar) |
| **Location** | `src/ui/package-lock.json` |
| **GHSA** | #8 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev — via `@electron/rebuild`) |
| **Description** | By crafting a malicious `.tar` archive, an attacker can write arbitrary files outside the intended extraction directory via hardlink path traversal. |
| **Fix** | Upgrade `tar` to `>= 6.2.1`. Upgrade `@electron/rebuild`. |
| **Status** | 📋 Pending |

### VULN-H09 — node-tar: Symbolic Link Path Traversal via Drive-Relative Linkpath
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` |
| **GHSA** | #12 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev) |
| **Description** | Symlink path traversal allowing file system escapes using drive-relative paths (Windows-specific). |
| **Fix** | Upgrade `tar`. |
| **Status** | 📋 Pending |

### VULN-H10 — node-tar: Arbitrary File Overwrite + Symlink Poisoning
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` |
| **GHSA** | #6 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev) |
| **Description** | Insufficient path sanitization allows overwriting arbitrary files and poisoning symlinks during tar extraction. |
| **Fix** | Upgrade `tar`. |
| **Status** | 📋 Pending |

### VULN-H11 — node-tar: Hardlink Path Traversal via Drive-Relative Linkpath
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` |
| **GHSA** | #11 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev) |
| **Description** | Arbitrary read/write via hardlink using drive-relative paths on Windows. |
| **Fix** | Upgrade `tar`. |
| **Status** | 📋 Pending |

### VULN-H12 — node-tar: Read/Write Escape via Hardlink + Symlink Chain
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` |
| **GHSA** | #9 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev) |
| **Description** | Arbitrary file read/write by escaping the extraction target via a chain of hardlinks and symlinks. |
| **Fix** | Upgrade `tar`. |
| **Status** | 📋 Pending |

### VULN-H13 — node-tar: Race Condition via Unicode Ligature Collisions on macOS APFS
| Field | Detail |
| :--- | :--- |
| **Package** | `tar` |
| **GHSA** | #7 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev) |
| **Description** | Race condition in path reservation using Unicode ligature collisions on case-insensitive macOS APFS file systems. |
| **Fix** | Upgrade `tar`. |
| **Status** | 📋 Pending (macOS only) |

### VULN-H14 — Lodash: Code Injection via `_.template` Import Key Names
| Field | Detail |
| :--- | :--- |
| **Package** | `lodash` |
| **GHSA** | #15 |
| **Severity** | 🟠 High |
| **Type** | Transitive (Dev — via build tooling) |
| **Description** | Specially crafted import key names in `_.template()` can lead to arbitrary JavaScript execution. |
| **Fix** | Upgrade `lodash` to `>=4.17.21`. Update build tooling. |
| **Status** | 📋 Pending (transitive — requires tooling upgrade) |

---

## 🟡 Moderate Vulnerabilities

### VULN-M01 — Vite: `server.fs.deny` Bypass via Backslash (Windows)
| GHSA | #4 | Package | `vite` (root `package-lock.json`) |
| :--- | :--- | :--- | :--- |
| **Description** | On Windows, using backslash characters in URL paths bypasses `server.fs.deny` restrictions. |
| **Fix** | Upgrade `vite`. |

### VULN-M02 — Vite: Path Traversal in `.map` Deps (root package-lock.json)
| GHSA | #5 | Package | `vite` (root) |
| :--- | :--- | :--- | :--- |
| **Description** | Same as VULN-H03 but tracked at root `package-lock.json`. |
| **Fix** | Upgrade `vite`. |

### VULN-M03 — Electron: `nodeIntegrationInWorker` Incorrect Scoping
| GHSA | #25 | Package | `electron` |
| :--- | :--- | :--- | :--- |
| **Description** | `nodeIntegrationInWorker` is not correctly scoped in shared renderer processes, potentially allowing unintended Node.js access in workers. |
| **Fix** | Upgrade `electron`. |

### VULN-M04 — Electron: AppleScript Injection in `app.moveToApplicationsFolder` (macOS)
| GHSA | #29 | Package | `electron` |
| :--- | :--- | :--- | :--- |
| **Description** | On macOS, `app.moveToApplicationsFolder()` is vulnerable to AppleScript injection. |
| **Fix** | Upgrade `electron`. |

### VULN-M05 — Electron: HTTP Response Header Injection in Custom Protocol Handlers
| GHSA | #17 | Package | `electron` |
| :--- | :--- | :--- | :--- |
| **Description** | Custom protocol handlers and `webRequest` can be used to inject arbitrary HTTP response headers. |
| **Fix** | Upgrade `electron`. |

### VULN-M06 — Lodash: Prototype Pollution via Array Path Bypass in `_.unset`/`_.omit`
| GHSA | #14 | Package | `lodash` |
| :--- | :--- | :--- | :--- |
| **Description** | Array path syntax can bypass prototype pollution protections in `_.unset` and `_.omit`. |
| **Fix** | Upgrade `lodash`. |

### VULN-M07 — xmldom: XML Injection via Unsafe CDATA Serialization
| GHSA | #13 | Package | `@xmldom/xmldom` |
| :--- | :--- | :--- | :--- |
| **Description** | Unsafe CDATA serialization allows injection of attacker-controlled markup into XML documents. |
| **Fix** | Upgrade `@xmldom/xmldom`. |

### VULN-M08 — follow-redirects: Auth Header Leak to Cross-Domain Redirect Targets
| GHSA | #38 | Package | `follow-redirects` |
| :--- | :--- | :--- | :--- |
| **Description** | Custom authentication headers are leaked to cross-domain redirect destinations. |
| **Fix** | Upgrade `follow-redirects` to `>=1.15.6`. |

### VULN-M09 — Rust/Tauri: `glib::VariantStrIter` Iterator/DoubleEndedIterator Inconsistency
| GHSA | #39 | Package | `glib` (Rust) |
| :--- | :--- | :--- | :--- |
| **Location** | `src/ui/src-tauri/Cargo.lock` |
| **Description** | Inconsistency between `Iterator` and `DoubleEndedIterator` implementations in `glib::VariantStrIter` could lead to undefined behavior. |
| **Fix** | Run `cargo update` to pull latest `glib`. |
| **Status** | 📋 Pending (`cargo-audit` not installed) |

---

## 🔵 Low Vulnerabilities (Summary)

| # | Package | Description |
| :--- | :--- | :--- |
| #4 | `vite` | `server.fs.deny` backslash bypass (root) |
| #5 | `vite` | `.map` path traversal (root) |
| Various | `electron` | Minor sandbox escape edge cases |
| Various | `tar` | Additional platform-specific traversal |

---

## 🟢 Acceptable Risks / False Positives (To Dismiss in GitHub UI)

### VULN-R01 — glib: `VariantStrIter` Iterator/DoubleEndedIterator Inconsistency
| Field | Detail |
| :--- | :--- |
| **Package** | `glib` (Rust) |
| **Location** | `src/ui/src-tauri/Cargo.lock` |
| **GHSA** | #39 |
| **Severity** | 🟡 Moderate |
| **Type** | Transitive (via `tauri` -> `wry` -> `webkit2gtk`) |
| **Description** | Inconsistency between Iterators in `glib::VariantStrIter` could lead to undefined behavior when modifying internal pointers. |
| **Analysis** | **False Positive for Sentinel.** Sentinel targets Windows, whereas `glib` and `webkit2gtk` are Linux-only dependencies in Tauri's tree. This code is never compiled into the Windows `.exe`, making exploitation impossible. |
| **Status** | 🟢 **Dismiss in UI** (Ignored pending upstream Tauri bump) |

### VULN-R02 — rand: ThreadRng Unreliable with Custom Logger
| Field | Detail |
| :--- | :--- |
| **Package** | `rand` (Rust) |
| **Location** | `src/ui/src-tauri/Cargo.lock` |
| **GHSA** | #40 |
| **Severity** | 🟡 Moderate |
| **Type** | Transitive (Build-time via `phf_generator`) |
| **Description** | Undefined behavior in `ThreadRng` when a custom logger accessing the RNG intersects with thread seeding. |
| **Analysis** | **Acceptable Risk.** This older version of `rand` is pulled exclusively during *build time* by `phf_generator` to generate code hashes. It is not compiled into the final Sentinel binary, and our build environment does not inject malicious loggers to trigger the memory corruption. |
| **Status** | 🟢 **Dismiss in UI** (Ignored pending upstream Tauri bump) |

---

## 📋 Remediation Summary

| Category | Strategy | Timeline |
| :--- | :--- | :--- |
| `axios` (Critical) | Upgrade to `>=1.8.2` | **Immediate** |
| `vite` (High) | Upgrade to `>=8.0.5` | **Immediate** |
| `electron` (High) | Upgrade; rebuild native modules | 24h |
| `tar` (High, Dev) | Indirect fix via `@electron/rebuild` upgrade | 24h |
| `lodash` (High, Dev) | Indirect fix via tooling upgrade | 48h |
| Rust `glib` (Moderate) | `cargo update` | 48h |

---

## 🛡️ CI/CD Controls Added

- **`dependency-audit.yml`**: Runs on every PR and daily. Blocks merges if critical vulnerabilities are detected.
- **`pr-security.yml`**: Sentinel static analysis on all PR code changes.

*Last updated: 2026-04-14. Next audit scheduled: 2026-04-15 (automated).*
