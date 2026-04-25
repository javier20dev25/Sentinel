# Sentinel V3 Architecture: Open Core & Cloud SaaS
*Strategic Technical Realignment*

## 1. The Death of the Desktop App
The previous strategy of building a Windows desktop app (Electron/Tauri) in `src/ui` is deprecated. Modern AppSec requires a headless CLI for local/CI execution and a centralized Web Dashboard for governance.

### Action Plan: The Great Purge
- Delete `src/ui/src`, `src/ui/electron`, `src/ui/src-tauri`.
- Extract the core mathematical engine (`src/ui/backend/scanner`) to `src/core`.
- Extract the CLI wrapper to `src/cli`.

## 2. The Repository Split (Open Core Strategy)
To protect intellectual property (IP) and server infrastructure code, the project must be split into two isolated environments.

### Repository A: `sentinel-cli` (Public / BSL-1.1 License)
- **Content:** The core Oracle Brain, static heuristics, mathematical damping, and the CLI binary.
- **License:** Business Source License (BSL). Free for local developer use and internal company CI/CD up to certain limits. Competitors cannot offer Sentinel as a managed service.
- **Compute:** Runs entirely on the user's hardware (Laptop or CI Runner). We incur $0 in compute costs for free users.

### Repository B: `sentinel-cloud` (Private / Closed Source)
- **Content:** 
  - The Next.js SaaS Dashboard (GitHub OAuth, Stripe Billing).
  - The `Intelligence Ingest API` (receives telemetry from the CLI).
  - The AI Agents (Twitter Bot, Midnight Cybersec Blog).
  - The Secure Database holding the raw vulnerability payloads for model training.
- **License:** All rights reserved. Trade Secret.

## 3. The Telemetry Flow (Intelligence Bridge)
When a user runs the CLI locally, Sentinel performs the scan. 
If `INTELLIGENCE_OPT_IN = true`:
1. The CLI strips PII (file paths, developer names).
2. It sends a JWT-authenticated JSON payload to `api.sentinel-appsec.com/ingest`.
3. **Payload Structure:**
   - **Public (Anonymized):** `type: "Supply Chain"`, `riskScore: 0.95`, `method: "AST Obfuscation"`. -> Goes to the public JSON feed for the community.
   - **Private (Raw):** The actual malicious code snippet. -> Goes to our private vault for AI training and the "Magazine".

## 4. Business Tiers Enforcement
- **Free Tier:** The CLI runs locally. The Web SaaS only acts as a viewer for up to 3 repos.
- **Pro Tier:** The SaaS allows creating custom Sentinel Rules (stored in our cloud, pulled dynamically by their CLI) and provides deep historical tracking.
- **Enterprise Tier:** The SaaS provisions dedicated Surgical Sandboxes in our cloud for extreme isolation testing, and full SLA support.
