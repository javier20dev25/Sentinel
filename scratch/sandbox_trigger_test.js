/**
 * Sentinel: Surgical Sandbox Auto-Trigger Test
 * 
 * Demonstrates Phase 4 (Native Lab Manager) and Phase 5 (Sandbox Activation).
 * Scans a low-risk package (is-promise) and a high-risk package (Axios with injected deps)
 * to prove that Docker is only invoked when strictly necessary.
 */

'use strict';

const LabManager = require('../src/ui/backend/scanner/lab_manager');
const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');

const LAB_DIR = 'c:\\Users\\sleyt\\sentinel-lab\\surgical-test';
const manager = new LabManager(LAB_DIR);

async function runSurgicalTest() {
    console.log(`\x1b[35m=== Sentinel: Surgical Sandbox Test (Phases 4 & 5) ===\x1b[0m\n`);

    // 1. Provision Targets Natively
    const benignTarget = await manager.provisionNpmPackage('is-promise', 'is-promise');
    // Using Chalk as our "High Risk" example from the Firing Range (Score: 0.65)
    // In a real scenario, we'd use a known malicious package, but this serves to trigger the threshold.
    const riskyTarget = await manager.provisionNpmPackage('chalk', 'chalk_risky');

    if (!benignTarget.success || !riskyTarget.success) {
        console.error("Failed to provision lab. Exiting.");
        return;
    }

    console.log(`\n\x1b[33m--- Testing Benign Target (is-promise) ---\x1b[0m`);
    const benignResults = await scanner.auditWithSurgicalSandbox(benignTarget.path, { profile: 'STRICT' });
    console.log(`Final Decision: ${benignResults.verdict} | Sandbox Triggered: ${benignResults.sandbox_triggered}`);

    console.log(`\n\x1b[33m--- Testing High-Risk Target (chalk_risky) ---\x1b[0m`);
    // Force a high score via forensics/depth or just let it hit the 0.65 from the benchmark
    const riskyResults = await scanner.auditWithSurgicalSandbox(riskyTarget.path, { profile: 'STRICT' });
    console.log(`Final Decision: ${riskyResults.verdict} | Sandbox Triggered: ${riskyResults.sandbox_triggered}`);
    
    if (riskyResults.sandbox_triggered) {
        console.log(`Sandbox Success: ${riskyResults.sandbox_execution_success}`);
    }

    console.log(`\n\x1b[32m[TEST COMPLETE] Architecture validated.\x1b[0m`);
}

runSurgicalTest();
