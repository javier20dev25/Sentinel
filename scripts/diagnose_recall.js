/**
 * Sentinel: Recall Diagnosis Tool (v1.0)
 * 
 * Target: Analyze the 15 malicious cases that under-escalated to REVIEW_HIGH_SIGNAL.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const ThreatMemory = require('../packages/sentinel-worker/core/scanner/threat_memory');

const CORPUS_DIR = path.join(__dirname, 'redteam_corpus', 'malicious');

function diagnose() {
    const files = fs.readdirSync(CORPUS_DIR).filter(f => f.endsWith('.json'));
    const underEscalated = [];

    for (const file of files) {
        const testCase = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, file), 'utf8'));
        const findings = testCase.signals.map(s => ({ intent: s, severity: 8, file: testCase.file }));
        
        const history = ThreatMemory.getRepoHistory(testCase.repo);
        const oracleCtx = {
            isAuthorized: true,
            user: 'diagnostics',
            mode: 'REPO',
            repoId: testCase.repo,
            historyOverride: history
        };

        const r = RiskOrchestrator.arbitrate(findings, testCase.repoProfile, oracleCtx);
        
        if (r.verdict !== 'BLOCK' && r.verdict !== 'SECURITY_HOLD') {
            underEscalated.push({
                file,
                id: testCase.id,
                verdict: r.verdict,
                impact: r.impactScore,
                confidence: r.decisionConfidence,
                signals: testCase.signals,
                profile: testCase.repoProfile,
                filters: r.reasoningTrace.filters,
                stages: r.reasoningTrace.stages
            });
        }
    }

    console.log(`\n=== RECALL DIAGNOSIS: ${underEscalated.length} CASES UNDER-ESCALATED ===\n`);

    // Group by Pattern
    const groups = {};
    for (const res of underEscalated) {
        const key = res.signals.sort().join('+');
        if (!groups[key]) groups[key] = [];
        groups[key].push(res);
    }

    for (const [pattern, items] of Object.entries(groups)) {
        console.log(`Pattern: [${pattern}] (${items.length} cases)`);
        console.log(`Representative: ${items[0].file} | Impact: ${items[0].impact} | Conf: ${items[0].confidence}`);
        console.log(`Filters: ${items[0].filters.join(', ')}`);
        console.log(`Stages: ${JSON.stringify(items[0].stages)}`);
        console.log('--------------------------------------------------');
    }
}

diagnose();
