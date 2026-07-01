/**
 * Sentinel: Determinism Auditor (v1.0)
 * 
 * DIRECTIVA: Mismo input -> Mismo veredicto. Cero deriva.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');

const LIVE_LOG = path.join(__dirname, '..', 'reports', 'live_scan', 'live_observations.jsonl');

const stats = {
    records_tested: 0,
    verdict_mismatch: 0,
    impact_drift: 0,
    hash_drift: 0,
    failures: []
};

async function verify() {
    if (!fs.existsSync(LIVE_LOG)) {
        console.error('ERROR: live_observations.jsonl not found.');
        process.exit(1);
    }

    const lines = fs.readFileSync(LIVE_LOG, 'utf8').trim().split('\n');
    
    for (let i = 0; i < lines.length; i++) {
        const stored = JSON.parse(lines[i]);
        stats.records_tested++;

        // REPLAY: Re-run arbitration with stored findings (provenance)
        const replayed = RiskOrchestrator.arbitrate(stored.provenance, 'default', {
            repoId: stored.repo,
            prId: stored.pr,
            commitSha: stored.sha,
            isAudit: true
        });

        // Comparison
        if (replayed.verdict !== stored.verdict) {
            stats.verdict_mismatch++;
            stats.failures.push(`Record ${i+1} [PR #${stored.pr}]: Verdict Mismatch (Stored: ${stored.verdict}, Replayed: ${replayed.verdict})`);
        }

        if (Math.round(replayed.impactScore) !== Math.round(stored.impact)) {
            stats.impact_drift++;
            stats.failures.push(`Record ${i+1} [PR #${stored.pr}]: Impact Drift (Stored: ${stored.impact}, Replayed: ${replayed.impactScore})`);
        }

        if (replayed.decision_hash !== stored.decision_hash) {
            stats.hash_drift++;
            stats.failures.push(`Record ${i+1} [PR #${stored.pr}]: Hash Drift (Stored: ${stored.decision_hash}, Replayed: ${replayed.decision_hash})`);
        }
    }

    console.log('====================================');
    console.log('SENTINEL REPLAY AUDIT');
    console.log('====================================');
    console.log(`Records Tested:     ${stats.records_tested}`);
    console.log(`Verdict Mismatch:   ${stats.verdict_mismatch}`);
    console.log(`Impact Drift:       ${stats.impact_drift}`);
    console.log(`Hash Drift:         ${stats.hash_drift}`);
    console.log(`Determinism:        ${stats.failures.length === 0 ? 'PASSED' : 'FAILED'}`);
    console.log('====================================\n');

    if (stats.failures.length > 0) {
        process.exit(1);
    }
}

verify().catch(console.error);
