# Changelog: Sentinel Security Engine

All notable changes to this project will be documented in this file.

## [3.6.1] - 2026-04-22
### Added
- **Licensing Transition**: Migrated from MIT to **Business Source License 1.1** (BSL) for enterprise IP protection.
- **Semantic Exit Code Contract**: Implementation of codes 0-3 for CI/CD deterministic orchestration.
- **Adaptive Security Gates**: New auto-escalation logic (Level 0-4) based on diff-surface analysis.
- **Binary Masquerading Detection**: Magic-byte signature validation against declared file extensions.
- **Forensic Audit Mode**: Optimized scan engine to bypass exclusion lists (e.g., node_modules) via `--forensic`.
- **Technical Specification**: Formal documentation of algorithmic complexity and heuristic logic.

### Changed
- **NPM Distribution Model**: Transitioned to "CLI-first" architecture with lightweight dependency footprint.
- **Renderer Evolution**: Transitioned to label-based reporting (`[SECURITY]`, `[POLICY]`) for enhanced CI log readability.
- **CLI Command Unification**: Merged redundant audit commands into a unified `sentinel audit` entrypoint.

> [!IMPORTANT]
> **Release Status: FEATURE FROZEN**
> Sentinel v3.6.1 is considered stable and feature-complete for this cycle. All subsequent updates will be limited to critical security hotfixes and rulepack maintenance.

## [3.5.0] - 2026-04-18
### Added
- **Intent Fingerprinting**: Implementation of the SARB (Security Analysis & Risk Baseline) engine.
- **Explainability Deck**: Terminal-based visualization of scoring metrics and signal weights.
- **Pre-Push Smart Hooks**: Git integration for advisory leak prevention.

### Improved
- **Entropy Heuristics**: Refined detection of base64 and packed payloads in source files.
- **Registry Poisoning Detection**: Optimized lockfile analyzer for large-scale dependency trees.

## [3.0.0] - 2024-11-12
### Initial Release
- **Core Engine**: Basic AST-based static analysis.
- **Local Dashboard**: Electron-based visualization of repository health.
- **Generic Ruleset**: Initial implementation of offensive pattern matching.
