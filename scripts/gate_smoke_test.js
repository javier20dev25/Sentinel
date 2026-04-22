/**
 * Sentinel: Phase 5.3 Smoke Test
 * 
 * Verifies:
 * 1. Policy Violation (Exit 2) for lockfile tampering.
 * 2. Security Finding (Exit 1) for malicious heuristics.
 * 3. Clean Scan (Exit 0).
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const TEST_DIR = path.join(__dirname, 'gate_smoke_test');

function setup() {
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true });
    fs.mkdirSync(TEST_DIR);
}

function runSentinel(args) {
    try {
        execSync(`node src/ui/cli/index.js ${args}`, { stdio: 'pipe' });
        return 0;
    } catch (e) {
        return e.status;
    }
}

console.log('🧪 Starting Sentinel Phase 5.3 Smoke Test...\n');

setup();

// Test 1: Clean Scan (Exit 0)
fs.writeFileSync(path.join(TEST_DIR, 'safe.js'), 'console.log("Hello World");');
const code0 = runSentinel(`scan ${TEST_DIR} --ci`);
console.log(`[TEST 1] Clean Scan: ${code0 === 0 ? '✅ PASSED' : '❌ FAILED'} (Exit: ${code0})`);

// Test 2: Policy Violation (Exit 2) - Lockfile Corruption (Invalid JSON)
fs.writeFileSync(path.join(TEST_DIR, 'package-lock.json'), '{ invalid: json }');
const code2 = runSentinel(`scan ${TEST_DIR} --ci`);
console.log(`[TEST 2] Policy Violation (Lockfile): ${code2 === 2 ? '✅ PASSED' : '❌ FAILED'} (Exit: ${code2})`);

// Test 3: Security Finding (Exit 1) - Malicious Heuristic
fs.writeFileSync(path.join(TEST_DIR, 'malware.js'), 'eval(Buffer.from("ZXZhbCgncnVuJyk=", "base64").toString());');
const code1 = runSentinel(`scan ${TEST_DIR} --ci`);
console.log(`[TEST 3] Security Finding (Malicious): ${code1 === 1 ? '✅ PASSED' : '❌ FAILED'} (Exit: ${code1})`);

// Test 4: Binary Masquerading (Using --fast to skip entropy and get pure POLICY exit 2)
const wasmBuffer = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
fs.writeFileSync(path.join(TEST_DIR, 'hidden.txt'), wasmBuffer);
const codeMasq = runSentinel(`scan ${TEST_DIR} --ci --fast`);
console.log(`[TEST 4] Binary Masquerading: ${codeMasq === 2 ? '✅ PASSED' : '❌ FAILED'} (Exit: ${codeMasq})`);

console.log('\n🏁 Smoke Test Finished.');

if (code0 === 0 && code1 === 1 && code2 === 2 && codeMasq === 2) {
    console.log('🌟 ALL GATE TESTS PASSED 🌟');
    process.exit(0);
} else {
    process.exit(1);
}
