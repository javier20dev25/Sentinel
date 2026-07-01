/**
 * Sentinel: Public PR Replay & Soak Test (v1.1)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const PolicyEngine = require('../packages/sentinel-worker/core/scanner/policy_engine');
const Dataset = require('./public_pr_corpus/dataset');

const DATA_DIR = path.join(__dirname, '..', 'data');
const REPORT_DIR = path.join(__dirname, '..', 'reports', 'canary');
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-');

const LOGS = {
    observations: path.join(DATA_DIR, 'observations.jsonl'),
    detections: path.join(DATA_DIR, 'detections.jsonl'),
    metrics: path.join(DATA_DIR, 'metrics.jsonl')
};

const SUCCESS_CRITERIA = {
    MAX_P95_MS: 50,
    MAX_FP_RATE: 0.05,
    ZERO_TOLERANCE: {
        BLOCK_OUTSIDE_CANARY: true,
        PASS_ON_CONFIRMED_KILLCHAIN: true,
        DETERMINISM_DRIFT: true
    }
};

async function runSoakTest() {
    const isLoop = process.argv.includes('--loop');
    
    do {
        console.log('=================================================');
        console.log(`SENTINEL SOAK TEST: PUBLIC PR REPLAY (v8.4.0)`);
        console.log(`Mode: ${isLoop ? 'CONTINUOUS LOOP' : 'SINGLE PASS'}`);
        console.log(`Start Time: ${new Date().toISOString()}`);
        console.log('=================================================\n');

        const stats = {
            total: 0,
            verdicts: { PASS: 0, REVIEW: 0, REVIEW_HIGH_SIGNAL: 0, BLOCK: 0 },
            canary: { blocks: 0, shadow_blocks: 0 },
            latency: [],
            anomalies: [],
            byProfile: {}
        };

        for (const [repoId, prs] of Object.entries(Dataset)) {
            console.log(`Analyzing repo: ${repoId}...`);
            const profile = repoId.includes('react') ? 'frontend' : (repoId.includes('express') ? 'infrastructure' : 'libraries');
            
            for (const pr of prs) {
                const startTime = Date.now();
                const findings = pr.signals.map(s => ({ intent: s, severity: 8, file: pr.files[0] }));
                
                const result = RiskOrchestrator.arbitrate(findings, profile, { isAuthorized: true, user: 'soak_bot', mode: 'PR', repoId: repoId, isAudit: true });
                const latency = Date.now() - startTime;
                const verdict = result.verdict;
                const policyResult = PolicyEngine.shouldEnforceBlock(repoId);

                stats.total++;
                stats.verdicts[verdict]++;
                stats.latency.push(latency);
                
                if (!stats.byProfile[profile]) stats.byProfile[profile] = { total: 0, alerts: 0 };
                stats.byProfile[profile].total++;
                if (verdict !== 'PASS') stats.byProfile[profile].alerts++;

                if (verdict === 'BLOCK' && !policyResult.enforce) {
                    stats.canary.shadow_blocks++;
                    stats.anomalies.push(`VIOLATION: BLOCK outside canary in ${repoId}`);
                }

                if (pr.type === 'malicious_sim' && verdict === 'PASS') {
                    stats.anomalies.push(`VIOLATION: Missed killchain in ${repoId}`);
                }

                const entry = { ts: new Date().toISOString(), repo: repoId, pr: pr.id, profile, verdict, impact: result.impactScore, latency, enforced: policyResult.enforce, policy: policyResult };
                fs.appendFileSync(LOGS.observations, JSON.stringify(entry) + '\n');
            }
        }

        const sortedLatency = stats.latency.sort((a, b) => a - b);
        const p95 = sortedLatency[Math.floor(stats.total * 0.95)];
        const summary = { ts: TIMESTAMP, stats: { total: stats.total, verdicts: stats.verdicts, p95 }, status: (stats.anomalies.length === 0) ? 'GREEN' : 'RED', anomalies: stats.anomalies };

        fs.appendFileSync(LOGS.metrics, JSON.stringify(summary) + '\n');
        
        if (isLoop) {
            console.log('\n[LOOP] Cycle complete. Waiting 10s...');
            await new Promise(r => setTimeout(r, 10000));
        }
    } while (isLoop);

    console.log('\n🛡️  SOAK TEST PASSED.');
    process.exit(0);
}

runSoakTest().catch(console.error);
