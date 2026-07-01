/**
 * Sentinel: Batch Replay Verification (v1.0)
 * 
 * Replays ALL decision hashes from the red team results
 * and reports determinism across the entire corpus.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const DataContract = require('../packages/sentinel-worker/core/scanner/data_contract');
const ThreatMemory = require('../packages/sentinel-worker/core/scanner/threat_memory');

const RESULTS_PATH = path.join(__dirname, '..', 'data', 'redteam', 'redteam_results.json');

// Ensure memory is loaded
ThreatMemory.getStats();

const results = JSON.parse(fs.readFileSync(RESULTS_PATH, 'utf8'));

let pass = 0;
let fail = 0;
const failures = [];

for (const original of results) {
    const repoProfile = original.repoProfile || original.repo_profile;
    const repo = original.repo || original.repoId;
    const file = original.file || 'unknown';
    const signals = original.signals || [];

    const findings = signals.map(s => ({ intent: s, severity: 8, file }));

    const oracleCtx = {
        isAuthorized: true,
        user: original.author || 'redteam_actor',
        mode: original.mode || 'REPO',
        isAudit: true,
        repoId: repo,
        historyOverride: original.historicalState
    };

    const rawResult = RiskOrchestrator.arbitrate(findings, repoProfile, oracleCtx);
    const canonical = DataContract.normalize(rawResult, {
        scanId: `scan-replay-${original.decisionHash}`,
        repoId: repo,
        repoProfile,
        file,
        author: oracleCtx.user
    });

    const replayed = DataContract.toObservationRecord(canonical, { file, includeTrace: true });

    const origImpact = original.effectiveImpact || original.effective_impact;
    const origConf = original.confidence || original.decisionConfidence;
    const origVerdict = original.verdict || original.actualVerdict;

    const drift = [];
    if (Math.abs(origImpact - replayed.effective_impact) > 0.01) drift.push('IMPACT');
    if (Math.abs(origConf - replayed.confidence) > 0.03) drift.push('CONFIDENCE');
    if (origVerdict !== replayed.verdict) drift.push('VERDICT');

    if (drift.length === 0) {
        pass++;
    } else {
        fail++;
        failures.push({
            id: original.id,
            hash: original.decisionHash,
            category: original.category,
            drift,
            original: { impact: origImpact, confidence: origConf, verdict: origVerdict },
            replayed: { impact: replayed.effective_impact, confidence: replayed.confidence, verdict: replayed.verdict }
        });
    }
}

console.log('=================================================');
console.log('BATCH REPLAY AUDIT');
console.log('=================================================\n');
console.log(`Total:  ${results.length}`);
console.log(`Pass:   ${pass}`);
console.log(`Fail:   ${fail}`);
console.log(`Rate:   ${((pass / results.length) * 100).toFixed(1)}%\n`);

if (failures.length > 0) {
    console.log('DRIFTED DECISIONS:');
    for (const f of failures) {
        console.log(`  ${f.id} [${f.category}] ${f.hash}: ${f.drift.join(', ')}`);
        console.log(`    Original:  impact=${f.original.impact} conf=${f.original.confidence} verdict=${f.original.verdict}`);
        console.log(`    Replayed:  impact=${f.replayed.impact} conf=${f.replayed.confidence} verdict=${f.replayed.verdict}`);
    }
    console.log(`\nRESULT: NON-DETERMINISTIC ❌`);
    process.exit(1);
} else {
    console.log('RESULT: ALL DECISIONS DETERMINISTIC ✅');
    process.exit(0);
}
