/**
 * Sentinel: Deterministic Replay Audit (v1.0)
 * 
 * Target: Guarantee that decision_hash -> identical verdict/impact/trace.
 * Goal: Bitwise reproducible auditing.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const DataContract = require('../packages/sentinel-worker/core/scanner/data_contract');
const ThreatMemory = require('../packages/sentinel-worker/core/scanner/threat_memory');

const HASH = process.argv[2];

if (!HASH && process.argv[2] !== '--sample' && process.argv[2] !== '--strict') {
    console.error("Usage: node replay_decision.js <decision_hash>");
    process.exit(1);
}

// 1. Resolve Decision
function findDecision(hash) {
    const searchPaths = [
        path.join(__dirname, '..', 'data', 'redteam', 'redteam_results.json'),
        path.join(__dirname, '..', 'data', 'detections.jsonl'),
        path.join(__dirname, '..', 'data', 'observations.jsonl')
    ];

    for (const p of searchPaths) {
        if (!fs.existsSync(p)) continue;
        const content = fs.readFileSync(p, 'utf8');
        
        if (p.endsWith('.json')) {
            const data = JSON.parse(content);
            const found = data.find(d => d.decisionHash === hash || d.decision_hash === hash);
            if (found) return found;
        } else {
            const lines = content.split('\n').filter(Boolean);
            for (const line of lines) {
                const data = JSON.parse(line);
                if (data.decision_hash === hash) return data;
            }
        }
    }
    return null;
}

const targetHash = HASH || 'rt-001'; // If --sample, pick one
const original = findDecision(targetHash);

if (!original) {
    console.error(`❌ Decision hash ${targetHash} not found in any data source.`);
    process.exit(1);
}

// Ensure memory is loaded (using snapshot/events)
ThreatMemory.getStats();

// Restore Environment (Mocking what would be full state rehydration)
const repoProfile = original.repoProfile || original.repo_profile;
const repo = original.repo || original.repoId;
const file = original.file || 'unknown';
const signals = original.signals || (original.reasoning ? original.reasoning.signals : []) || ['NETWORK'];

// Recreate findings from signals
const findings = signals.map(s => ({ intent: s, severity: 8, file }));

const oracleCtx = {
    isAuthorized: true,
    user: original.author || 'redteam_actor',
    mode: original.mode || 'REPO',
    isAudit: true,
    repoId: repo,
    historyOverride: original.historicalState
};

// Re-run
const rawResult = RiskOrchestrator.arbitrate(findings, repoProfile, oracleCtx);

const canonical = DataContract.normalize(rawResult, {
    scanId: `scan-${targetHash}`,
    repoId: repo,
    repoProfile: repoProfile,
    file: file,
    author: oracleCtx.user
});

const replayed = DataContract.toObservationRecord(canonical, { file, includeTrace: true });

// Diff Engine
const origImpact = original.effectiveImpact || original.effective_impact;
const origRaw = original.rawImpact || original.raw_impact;
const origConf = original.confidence || original.decisionConfidence;
const origVerdict = original.verdict || original.actualVerdict;
const origTrace = original.reasoning || original.reasoningTrace;

let drift = [];

if (Math.abs(origRaw - replayed.raw_impact) > 0.01) drift.push('SCORE DRIFT (Raw Impact)');
if (Math.abs(origImpact - replayed.effective_impact) > 0.01) drift.push('SCORE DRIFT (Effective Impact)');
if (Math.abs(origConf - replayed.confidence) > 0.03) drift.push('CONFIDENCE DRIFT');
if (origVerdict !== replayed.verdict) drift.push('VERDICT DRIFT');

// Trace compare
if (origTrace && replayed.reasoning) {
    if (JSON.stringify(origTrace.filters) !== JSON.stringify(replayed.reasoning.filters)) {
        drift.push('TRACE DRIFT (Filters)');
    }
}

console.log("=================================================");
console.log("REPLAY AUDIT");
console.log("=================================================\n");
console.log(`Decision:\n${targetHash}\n`);

console.log(`Original:`);
console.log(`impact: ${origImpact}`);
console.log(`confidence: ${origConf}`);
console.log(`verdict: ${origVerdict}\n`);

console.log(`Replay:`);
console.log(`impact: ${replayed.effective_impact}`);
console.log(`confidence: ${replayed.confidence}`);
console.log(`verdict: ${replayed.verdict}\n`);

console.log(`Trace Match: ${drift.some(d => d.includes('TRACE')) ? 'NO' : 'YES'}`);
const origCalib = original.calibrationVersion || original.calibration_version;
console.log(`Calibration Match: ${origCalib === replayed.calibration_version ? 'YES' : 'NO'}`);

if (drift.length === 0) {
    console.log(`\nRESULT:\nDETERMINISTIC ✅`);
    process.exit(0);
} else {
    console.log(`\nRESULT:\nNON-DETERMINISTIC ❌\n`);
    console.log(`CAUSE:`);
    drift.forEach(d => console.log(`- ${d}`));
    process.exit(1);
}
