/**
 * Sentinel: Security Gate CLI (v1.0)
 * 
 * The primary entry point for CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).
 * Implements "Security as Code" by enforcing organizational policies on PRs.
 */

'use strict';

const path = require('path');
const scanner = require('./index');
const GateOrchestrator = require('./gate_orchestrator');
const PolicyEngine = require('./policy_engine');

async function runSecurityGate(targetPath, modifiedFiles = []) {
    console.log(`\x1b[35m=== Sentinel: CI/CD Security Gate ===\x1b[0m`);
    console.log(`Target: ${path.resolve(targetPath)}`);
    console.log(`Policy: ${PolicyEngine.getPolicyInfo().name} [Mode: ${PolicyEngine.getPolicyInfo().enforcement}]`);

    // 1. Resolve Gate Level (Adaptive Scan)
    const gate = GateOrchestrator.resolveGateLevel(modifiedFiles);
    console.log(`\x1b[34m[GATE] Detected Level: ${GateOrchestrator.getLevelLabel(gate.level)}\x1b[0m`);
    console.log(`Reason: ${gate.reason}`);

    // 2. Execute Audit (Surgical Sandbox Enabled)
    // We use 'STRICT' profile for CI/CD gates by default.
    const results = await scanner.auditWithSurgicalSandbox(targetPath, { 
        profile: 'STRICT', 
        forensics: true 
    });

    console.log(`\n\x1b[33m[RESULTS] Final Risk Score: ${results.riskScore.toFixed(2)} (${results.verdict})\x1b[0m`);
    
    // 3. Enforcement Logic
    const isStrict = PolicyEngine.isStrictMode();
    const shouldBlock = results.riskScore >= 0.70; // Hard block threshold for CI

    // 3. Telemetry Ingestion (Non-blocking fail-safe)
    const telemetry = require('./telemetry');
    await telemetry.reportIntelligence(results, targetPath);

    if (shouldBlock) {
        console.log(`\n\x1b[31m[BLOCK] Security Policy Violation!\x1b[0m`);
        console.log(`Veredict: ${results.verdict}`);
        console.log(`Threshold 0.70 exceeded.`);
        
        if (isStrict) {
            console.log(`\n\x1b[41m*** CI/CD FAIL: ACTION REQUIRED ***\x1b[0m`);
            if (process.env.LAST_SENTINEL_EVENT_ID) {
                console.log(`Event Reference: ${process.env.LAST_SENTINEL_EVENT_ID}`);
            }
            process.exit(1);
        } else {
            console.log(`\n\x1b[33m[ADVISORY] Block suppressed (Advisory Mode active).\x1b[0m`);
        }
    } else {
        console.log(`\n\x1b[32m[PASS] Security Gate cleared. No critical threats found.\x1b[0m`);
        process.exit(0);
    }
}

// CLI Argument Handling
const args = process.argv.slice(2);
if (args.length > 0) {
    const target = args[0];
    const files = args.slice(1);
    runSecurityGate(target, files);
}

module.exports = { runSecurityGate };
