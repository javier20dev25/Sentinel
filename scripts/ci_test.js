/**
 * Sentinel: CI Contract Suite (v1.0)
 * 
 * DIRECTIVA: Validar el contrato de datos mediante pruebas positivas y negativas.
 */

'use strict';

const { execSync } = require('child_process');
const path = require('path');

const SCRIPTS_DIR = __dirname;
const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'live_prs');

const suite = [
    { name: 'Benign Pass', file: 'benign_pass.json', expectFail: false },
    { name: 'Risk Network', file: 'risk_network.json', expectFail: false },
    { name: 'Malformed Fixture', file: 'malformed_fixture.json', expectFail: true },
    { name: 'SHA Adulteration', file: 'sha_corrupted.json', expectFail: true },
    { name: 'Provenance Truncation', file: 'provenance_truncated.json', expectFail: true },
    { name: 'Hash Drift (Impact Tampering)', file: 'hash_drift.json', expectFail: true }
];

console.log('====================================');
console.log('SENTINEL CI CONTRACT SUITE');
console.log('====================================');

let suiteFailed = false;

for (const test of suite) {
    console.log(`Running Test: [${test.name}]`);
    const fixturePath = path.join(FIXTURES_DIR, test.file);
    let exitCode = 0;
    
    try {
        // Ejecutamos en silencio para no saturar el output CI, solo nos importa el exit code
        execSync(`node ${path.join(SCRIPTS_DIR, 'verify_golden_fixture.js')} ${fixturePath}`, { stdio: 'ignore' });
    } catch (error) {
        exitCode = error.status || 1;
    }

    const testPassed = test.expectFail ? (exitCode !== 0) : (exitCode === 0);
    
    console.log(`  Expected Fail: ${test.expectFail}`);
    console.log(`  Actual Exit  : ${exitCode}`);
    console.log(`  Status       : ${testPassed ? 'OK' : 'FAILED'}\n`);
    
    if (!testPassed) suiteFailed = true;
}

console.log('====================================');
console.log(`CI SUITE RESULT: ${suiteFailed ? 'FAILED' : 'PASSED'}`);
console.log('====================================');

if (suiteFailed) process.exit(1);
