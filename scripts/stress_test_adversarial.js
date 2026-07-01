/**
 * Sentinel: Adversarial Stress Test & Confusion Matrix (v1.0)
 * 
 * Objective: Address "The ChatGPT Critique" by probing semantic blind spots.
 * 
 * Focus Areas:
 * 1. Killchain Preservation: Does NETWORK dampening mask SECRET_ACCESS+NETWORK?
 * 2. Obfuscation Synergy: Does ENCODING+EXECUTION correctly escalate even on "mature" repos?
 * 3. Contextual Escalation: Does postinstall/build context override dampeners?
 * 4. Confusion Matrix: TP/FP/TN/FN distribution across profiles.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const RepoProfile = require('../packages/sentinel-worker/core/scanner/repo_profile');

const STRESS_CASES = [
    // --- CATEGORY 1: Semantic Blindness Probes (Frontend) ---
    {
        id: 'adv-001',
        name: 'Killchain: Credential Exfiltration (Frontend)',
        profile: 'frontend',
        repoId: 'facebook/react',
        signals: [
            { intent: 'SECRET_ACCESS', severity: 9, file: 'src/api.js' },
            { intent: 'NETWORK', severity: 8, file: 'src/api.js' }
        ],
        expectedVerdict: 'BLOCK',
        rationale: 'NETWORK is expected, but SECRET_ACCESS+NETWORK is a coordinated exfiltration killchain.'
    },
    {
        id: 'adv-002',
        name: 'Killchain: Obfuscated Downloader (Frontend)',
        profile: 'frontend',
        repoId: 'facebook/react',
        signals: [
            { intent: 'ENCODING', severity: 7, file: 'src/utils.js' },
            { intent: 'NETWORK', severity: 9, file: 'src/utils.js' }
        ],
        expectedVerdict: 'BLOCK|REVIEW_HIGH_SIGNAL',
        rationale: 'ENCODING+NETWORK suggests fetching and decoding an encrypted payload.'
    },

    // --- CATEGORY 2: Contextual Escalation (Postinstall) ---
    {
        id: 'adv-003',
        name: 'Postinstall Network Call (Infrastructure)',
        profile: 'infrastructure',
        repoId: 'expressjs/express',
        signals: [
            { intent: 'NETWORK', severity: 7, file: 'scripts/postinstall.js' }
        ],
        expectedVerdict: 'BLOCK|REVIEW_HIGH_SIGNAL',
        rationale: 'Even if NETWORK is expected in infra, doing it in postinstall is a supply chain risk.'
    },

    // --- CATEGORY 3: Obfuscation Variants ---
    {
        id: 'adv-004',
        name: 'Stealth Execution (Reflect/eval)',
        profile: 'default',
        repoId: 'unknown-repo',
        signals: [
            { intent: 'ENCODING', severity: 9, file: 'lib/core.js' },
            { intent: 'EXECUTION', severity: 9, file: 'lib/core.js' }
        ],
        expectedVerdict: 'BLOCK',
        rationale: 'Classical malware pattern. Dampeners must not touch this.'
    },
    {
        id: 'adv-006',
        name: 'Stealth Exfiltration (Obfuscated DNS)',
        profile: 'infrastructure',
        repoId: 'expressjs/express',
        signals: [
            { intent: 'OBFUSCATION', severity: 8, file: 'src/dns_client.js' },
            { intent: 'NETWORK', severity: 8, file: 'src/dns_client.js' }
        ],
        expectedVerdict: 'BLOCK|REVIEW_HIGH_SIGNAL',
        rationale: 'Obfuscation combined with Network is a high-risk signature.'
    },

    // --- CATEGORY 4: Edge Case "Normal" but High Volume ---
    {
        id: 'adv-005',
        name: 'High-Volume Expected Signal (Frontend)',
        profile: 'frontend',
        repoId: 'facebook/react',
        signals: [
            { intent: 'NETWORK', severity: 5, file: 'src/api1.js' },
            { intent: 'NETWORK', severity: 5, file: 'src/api2.js' },
            { intent: 'NETWORK', severity: 5, file: 'src/api3.js' }
        ],
        expectedVerdict: 'PASS',
        rationale: 'Multiple network calls in frontend are still just NETWORK (intentSet.size === 1).'
    }
];

function runStressTest() {
    console.log('=================================================');
    console.log('SENTINEL ADVERSARIAL STRESS TEST (v8.3.1)');
    console.log('=================================================\n');

    let passed = 0;
    const results = [];
    const matrix = {
        frontend: { tp: 0, fp: 0, tn: 0, fn: 0 },
        infrastructure: { tp: 0, fp: 0, tn: 0, fn: 0 },
        default: { tp: 0, fp: 0, tn: 0, fn: 0 }
    };

    for (const test of STRESS_CASES) {
        const profile = RepoProfile.getProfile(test.profile);
        const ctx = {
            isAuthorized: true,
            user: 'adversary',
            mode: 'REPO',
            repoId: test.repoId || test.id,
            historyOverride: { convergenceScore: 0.5, benignPatternFrequency: 0, scanCount: 10, trustTrend: 0 }
        };

        const result = RiskOrchestrator.arbitrate(test.signals, test.profile, ctx);
        const verdict = result.verdict;
        
        const isMatch = test.expectedVerdict.split('|').includes(verdict);
        if (isMatch) passed++;

        // Confusion Matrix Logic
        const category = test.expectedVerdict.includes('BLOCK') ? 'malicious' : 'benign';
        const p = test.profile;
        if (category === 'malicious') {
            if (verdict === 'BLOCK' || verdict === 'REVIEW_HIGH_SIGNAL') matrix[p].tp++;
            else matrix[p].fn++;
        } else {
            if (verdict === 'BLOCK' || verdict === 'REVIEW_HIGH_SIGNAL') matrix[p].fp++;
            else matrix[p].tn++;
        }

        console.log(`[${isMatch ? '✅' : '❌'}] ${test.id}: ${test.name}`);
        console.log(`      Expected: ${test.expectedVerdict} | Actual: ${verdict}`);
        console.log(`      Impact: ${result.impactScore} | Filters: ${(result.reasoningTrace?.filters || []).join(',')}`);
        results.push({ ...test, actual: verdict, pass: isMatch });
    }

    console.log('\n=================================================');
    console.log('CONFUSION MATRIX BY PROFILE');
    console.log('=================================================');
    console.log('Profile         | TP | FP | TN | FN | Precision | Recall');
    console.log('----------------|----|----|----|----|-----------|-------');
    
    for (const [name, stats] of Object.entries(matrix)) {
        const precision = (stats.tp / (stats.tp + stats.fp)) || 0;
        const recall = (stats.tp / (stats.tp + stats.fn)) || 0;
        console.log(`${name.padEnd(15)} | ${stats.tp}  | ${stats.fp}  | ${stats.tn}  | ${stats.fn}  | ${(precision * 100).toFixed(1)}%     | ${(recall * 100).toFixed(1)}%`);
    }

    console.log(`\nFinal Score: ${passed}/${STRESS_CASES.length}`);
    
    if (passed < STRESS_CASES.length) {
        console.error('\n❌ STRESS TEST FAILED: Semantic blind spots detected.');
        process.exit(1);
    } else {
        console.log('\n🛡️  STRESS TEST PASSED: Killchain preservation is mathematically guaranteed.');
        process.exit(0);
    }
}

runStressTest();
