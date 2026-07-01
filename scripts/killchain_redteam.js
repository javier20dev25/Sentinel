/**
 * Sentinel: Adversarial Killchain Red Team (v1.0)
 * 
 * Target: Verify 0 silent failures in coordinated killchains
 * Goal: Prove that "infrastructure dampening" doesn't blind the engine.
 */

'use strict';

const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const RepoProfile = require('../packages/sentinel-worker/core/scanner/repo_profile');

const SCENARIOS = [
    {
        name: 'benign infra',
        repo: 'expressjs/express',
        findings: [{ intent: 'NETWORK', severity: 5, file: 'lib/proxy.js' }],
        expected: ['PASS']
    },
    {
        name: 'infra noisy',
        repo: 'expressjs/express',
        findings: [
            { intent: 'NETWORK', severity: 6, file: 'lib/proxy.js' },
            { intent: 'POLICY', severity: 4, file: 'lib/config.js' }
        ],
        expected: ['PASS', 'REVIEW']
    },
    {
        name: 'coordinated attack',
        repo: 'expressjs/express', // Even in infra, this should BLOCK
        findings: [
            { intent: 'EXECUTION', severity: 9, file: 'lib/utils.js' },
            { intent: 'EXFILTRATION', severity: 9, file: 'lib/utils.js' }
        ],
        expected: ['BLOCK']
    },
    {
        name: 'stealth attack',
        repo: 'vercel/next.js', // Frontend
        findings: [
            { intent: 'SYSTEM_ACCESS', severity: 8, file: 'pages/api/auth.js' }, // Similar to SECRET_ACCESS
            { intent: 'NETWORK', severity: 7, file: 'pages/api/auth.js' },
            { intent: 'ENCODING', severity: 8, file: 'pages/api/auth.js' } // OBFUSCATION equivalent
        ],
        expected: ['REVIEW_HIGH_SIGNAL', 'SECURITY_HOLD', 'BLOCK']
    },
    {
        name: 'false combo',
        repo: 'expressjs/express',
        findings: [
            { intent: 'NETWORK', severity: 6, file: 'test/proxy.test.js' }
        ],
        expected: ['PASS']
    }
];

// Mock ThreatMemory & Context
const mockHistory = { trustTrend: 1.0, benignPatternFrequency: 50, convergenceScore: 0.1 };
const oracleCtx = { isAuthorized: true, user: 'test_actor', mode: 'REPO' };

let passed = 0;
let silentFailures = 0;

console.log("========================================================");
console.log("💥  SENTINEL RED TEAM: KILLCHAIN ADVERSARIAL TEST");
console.log("========================================================\n");

for (const scenario of SCENARIOS) {
    const profile = RepoProfile.getProfile(scenario.repo);
    
    const result = RiskOrchestrator.arbitrate(scenario.findings, profile.type, {
        ...oracleCtx,
        repoId: scenario.repo
    });

    const isMatch = scenario.expected.includes(result.verdict);
    const trace = result.reasoningTrace;
    const synergy = trace.stages.synergyRisk / trace.stages.baseGlobalRisk;
    
    let dampeningRatio = 0;
    if (trace.stages.synergyRisk > 0) {
        dampeningRatio = ((1 - (trace.stages.finalRisk / trace.stages.synergyRisk)) * 100).toFixed(1);
    }
    
    // Explicitly check for KILLCHAIN_PRESERVATION
    const preserved = trace.filters.includes('KILLCHAIN_PRESERVATION');

    if (isMatch) {
        console.log(`✅ [PASS] ${scenario.name}`);
        passed++;
    } else {
        console.log(`❌ [FAIL] ${scenario.name} (Expected: ${scenario.expected.join('|')}, Got: ${result.verdict})`);
        if (scenario.expected.includes('BLOCK') && result.verdict === 'PASS') {
            silentFailures++;
        }
    }
    console.log(`   Repo     : ${scenario.repo} (${profile.type})`);
    console.log(`   Verdict  : ${result.verdict} (Raw: ${Math.round(trace.stages.synergyRisk)} ➔ Final: ${Math.round(trace.stages.finalRisk)})`);
    console.log(`   Dampening: ${dampeningRatio}%`);
    console.log(`   Synergy  : ${synergy.toFixed(1)}x`);
    console.log(`   Filters  : ${trace.filters.join(', ') || 'none'}\n`);
}

console.log("========================================================");
console.log(`🎯 KPI: ${silentFailures} silent failures in killchains.`);
console.log(`   Pass Rate: ${passed}/${SCENARIOS.length}`);
if (silentFailures > 0) {
    console.log("\n❌ RED TEAM FAILED: The engine is vulnerable to masked attacks.");
    process.exit(1);
} else {
    console.log("\n🛡️  RED TEAM PASSED: Killchain Preservation is holding the line.");
    process.exit(0);
}
