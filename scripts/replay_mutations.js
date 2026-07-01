/**
 * Sentinel: Mutation Replay Engine (v1.0)
 * 
 * Target: Validate v8.4.0 against 180+ adversarial mutations.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');

const MUTATED_DIR = path.join(__dirname, '..', 'scripts', 'redteam_corpus', 'mutated');

function runMutationTest() {
    console.log('=================================================');
    console.log('SENTINEL ADVERSARIAL MUTATION TEST (v1.0)');
    console.log('=================================================\n');

    const mutatedFiles = fs.readdirSync(MUTATED_DIR).filter(f => f.endsWith('.json'));
    const results = {
        total: 0,
        blocks: 0,
        failures: []
    };

    for (const file of mutatedFiles) {
        const testCase = JSON.parse(fs.readFileSync(path.join(MUTATED_DIR, file), 'utf8'));
        const findings = testCase.signals.map(s => ({ intent: s, severity: 8, file: testCase.file || 'mutated_src.js' }));
        
        // Use enterprise profile to test real enforcement, avoiding TEST_CONTEXT suppression
        const result = RiskOrchestrator.arbitrate(findings, 'enterprise', { 
            isAuthorized: true, 
            user: 'mutation_bot',
            repoId: 'org-alpha/production-core' // Force production context
        });
        
        results.total++;
        if (result.verdict === 'BLOCK' || result.verdict === 'SECURITY_HOLD') {
            results.blocks++;
        } else {
            results.failures.push({
                id: testCase.id,
                type: testCase.mutation_type,
                verdict: result.verdict,
                impact: result.impactScore,
                conf: result.decisionConfidence,
                signals: testCase.signals
            });
        }
    }

    const recall = (results.blocks / results.total) * 100;

    console.log(`Mutation Recall: ${recall.toFixed(1)}% (${results.blocks}/${results.total})`);
    
    if (results.failures.length > 0) {
        console.log('\n--- TOP FAILURES ---');
        results.failures.slice(0, 5).forEach(f => {
            console.log(`[${f.type}] ${f.id} -> Verdict: ${f.verdict} (Impact: ${f.impact})`);
        });
    }

    if (recall === 100) {
        console.log('\n🛡️  MUTATION LAB PASSED: Semantic invariants are indestructible.');
        process.exit(0);
    } else if (recall >= 95) {
        console.log('\n⚠️  MUTATION LAB WARNING: High coverage, but some edge cases escaped.');
        process.exit(0);
    } else {
        console.error('\n❌ MUTATION LAB FAILED: Vulnerable to adversarial mutations.');
        process.exit(1);
    }
}

runMutationTest();
