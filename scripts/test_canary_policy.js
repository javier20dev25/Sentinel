/**
 * Sentinel: Canary Policy Validation (v1.0)
 * 
 * Verifies the staged rollout logic for v8.4.0.
 */

'use strict';

const PolicyEngine = require('../packages/sentinel-worker/core/scanner/policy_engine');

const TEST_REPOS = [
    { id: 'facebook/react', expectedEnforcement: true, description: 'Whitelisted Canary (Frontend)' },
    { id: 'expressjs/express', expectedEnforcement: true, description: 'Whitelisted Canary (Infra)' },
    { id: 'lodash/lodash', expectedEnforcement: true, description: 'Whitelisted Canary (Library)' },
    { id: 'unknown/project', expectedEnforcement: false, description: 'Shadow/Advisory Repo' }
];

function testCanary() {
    console.log('=================================================');
    console.log('SENTINEL CANARY POLICY VALIDATION');
    console.log(`Active Mode: ${PolicyEngine.getPolicyInfo().enforcement}`);
    console.log('=================================================\n');

    let passed = 0;
    for (const repo of TEST_REPOS) {
        const actual = PolicyEngine.shouldEnforceBlock(repo.id);
        const success = actual === repo.expectedEnforcement;
        if (success) passed++;

        console.log(`[${success ? '✅' : '❌'}] ${repo.id} (${repo.description})`);
        console.log(`      Should Enforce Block? ${actual}`);
    }

    console.log(`\nFinal Score: ${passed}/${TEST_REPOS.length}`);
    if (passed === TEST_REPOS.length) {
        console.log('\n🛡️  CANARY POLICY VERIFIED: Staged rollout is operationally safe.');
        process.exit(0);
    } else {
        console.error('\n❌ CANARY POLICY FAILED: Incorrect enforcement logic.');
        process.exit(1);
    }
}

testCanary();
