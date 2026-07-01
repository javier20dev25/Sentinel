/**
 * Sentinel: Golden Fixture Verifier (v1.0)
 * 
 * DIRECTIVA: Estabilidad ante cambios de código.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');

const FIXTURE_PATH = process.argv[2] || path.join(__dirname, '..', 'fixtures', 'live_prs', 'benign_pass.json');

function verify() {
    try {
        if (!fs.existsSync(FIXTURE_PATH)) {
            console.error(`ERROR: Golden fixture not found at ${FIXTURE_PATH}`);
            process.exitCode = 1;
            return;
        }

        const gold = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
        
        console.log(`[GOLDEN] Verifying PR: ${gold.repo} #${gold.pr}`);
        console.log('====================================');
        console.log(`GOLDEN FIXTURE AUDIT [${gold.fixture_type || 'UNKNOWN'}]`);
        console.log('====================================');
        
        // Strict Contract Checks
        const contractErrors = [];
        if (!gold.fixture_type) contractErrors.push('Missing fixture_type field');
        if (!gold.decision_hash) contractErrors.push('Missing decision_hash field');
        
        // Tamper Resistance: SHA validation
        const shaRegex = /^[a-f0-9]{7,40}$/;
        if (!gold.sha || !shaRegex.test(gold.sha)) {
            contractErrors.push('Invalid SHA format');
        }

        // Tamper Resistance: Provenance truncation checks
        if (gold.fixture_type === 'risk') {
            if (!gold.provenance || gold.provenance.length === 0) {
                contractErrors.push('Risk fixture must have provenance');
            } else {
                const truncated = gold.provenance.some(p => !p.hunk || !p.excerpt);
                if (truncated) contractErrors.push('Incomplete provenance (missing hunk/excerpt)');
            }
        }

        if (contractErrors.length > 0) {
            console.log('Result: FAILED');
            console.log('Reason: Contract Violation');
            contractErrors.forEach(err => console.log(` - ${err}`));
            console.log('====================================\n');
            process.exitCode = 1;
            return;
        }
        
        const replayed = RiskOrchestrator.arbitrate(gold.provenance, 'default', {
            repoId: gold.repo,
            prId: gold.pr,
            commitSha: gold.sha,
            isAudit: true
        });

        const checks = [
            { name: 'Type', expected: gold.fixture_type, actual: gold.fixture_type },
            { name: 'Verdict', expected: gold.verdict, actual: replayed.verdict },
            { name: 'Impact', expected: Math.round(gold.impact), actual: Math.round(replayed.impactScore) },
            { name: 'Hash', expected: gold.decision_hash, actual: replayed.decision_hash },
            { name: 'ProvCount', expected: (gold.provenance || []).length, actual: (replayed.provenance || []).length }
        ];

        let failed = false;
        
        checks.forEach(c => {
            const isMissing = c.expected === undefined || c.actual === undefined;
            const isMismatch = c.expected !== c.actual;
            const ok = !isMissing && !isMismatch;

            console.log(`${c.name.padEnd(10)}: ${ok ? 'OK' : 'FAIL'} (Exp: ${c.expected}, Act: ${c.actual})`);
            if (!ok) failed = true;
        });

        console.log('====================================');
        console.log(`Result: ${failed ? 'FAILED' : 'PASSED'}`);
        console.log('====================================\n');

        if (failed) process.exitCode = 1;

    } catch (err) {
        console.log('Result: FAILED');
        console.log('Reason: Engine Exception during replay');
        console.log(`Error : ${err.message}`);
        console.log('====================================\n');
        process.exitCode = 1;
    }
}

verify();
