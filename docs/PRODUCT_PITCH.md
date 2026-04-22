# Sentinel: The Enterprise-Grade Governance Pipeline

## 1. The Problem
Modern Security pipelines and standard SAST tools detect vulnerabilities, but they fail to explain or govern their decisions. 
Current tools act as noisy "black boxes." When a pull request is blocked by a critical detection, Security Operations (SecOps) and Engineering teams waste countless hours arguing about the relevance of the threat. The tools provide a score, but lack trace reliability, operational rule versioning, or human-readable defense narratives. The result is developer fatigue and unreliable CI/CD enforcement.

## 2. The Solution
Sentinel is not a simple security scanner; it is an auditable decision engine built for CI/CD pipelines. Sentinel does not just detect threats; it makes them auditable, versioned, and defendable. By bridging the gap between deep abstract syntax tree analysis and clear, human-accessible governance metrics, Sentinel ensures that every critical block is backed by documented evidence and structured data.

## 3. The Core Differentiator: Enterprise Contract Governance
Sentinel eliminates "guesswork" by forcing a rigid Output Contract against its own backend mathematical detectors:

- **Rulepack Versioning (`rulepack_version`):** Allows teams to identify exactly what maturity level of detection logic was active during a scan, guaranteeing reproducibility and comparison across months of operation. 
- **Traceability (`rule_id`):** Every detection is signed with a semantic prefix (e.g., `SARB-EXEC-155`) enabling precise integration into external SIEMs or internal Jira automated tickets.
- **Auditability (`explanation`):** Each threat brings its own English-language baseline explanation of the matched signals and behavior, bridging the technical gap.
- **Automated Quality Gates (CI Enforcement):** Sentinel implements hard Quality Gates in its own source base. Regressions in False Positive Rates natively abort Sentinel's own deployments, serving as an immutable pledge to quality. 
- **Fast Path Adoption:** Sentinel offers a high-velocity mode triggered via `--fast`, allowing teams to ingest critical security findings in under 3 seconds without fragmenting the core detection logic.

## 4. Operational Demo & Evidence Visualization
Sentinel incorporates a strictly separated "Offline-First" visual validation layer tailored for forensics:
- **Contract Driven Rendering:** The Dashboard relies solely on Sentinel's JSON Governance outputs without interacting with raw source repositories, preventing secondary machine exploitation.
- **Formal Audit Evidence DrillDown:** A dedicated forensic panel that organizes the Risk Score, Rule ID, matched syntax patterns, and the Formal Audit Explanation sequentially.
- **Fail-Closed Validation Schema:** If a JSON manipulation attempt occurs, the User Interface rejects the forensic report, maintaining absolute data validity through Zod Schema strict bounding.

## 5. The Value Claim
Sentinel is not a scanner. It is an auditable decision engine for CI security pipelines. It converts detection into operational evidence for real security teams.
