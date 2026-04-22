/**
 * Sentinel Release Gate (SRG)
 * 
 * Formal validation of engine integrity, semantic exit codes, and NPM distribution 
 * viability. This script serves as the final blocker for publication.
 */

const { spawnSync, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const CLI_BIN = path.join(__dirname, '..', 'src', 'ui', 'cli', 'index.js');
const TEST_DIR = path.join(__dirname, 'release_validation_tmp');

console.log('Sentinel Release Validation — Infrastructure Audit (v3.6.1)');
console.log('─'.repeat(60));

function setup() {
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true });
    fs.mkdirSync(TEST_DIR);
}

function runSentinel(args) {
    return spawnSync('node', [CLI_BIN, ...args], { encoding: 'utf-8', cwd: TEST_DIR });
}

let failed = 0;

function assert(name, res, expectedStatus, msg) {
    process.stdout.write(`[GATE] ${name.padEnd(40)}... `);
    if (res.status === expectedStatus) {
        console.log('PASSED');
    } else {
        console.log('FAILED');
        console.error(`       Expected: ${expectedStatus} | Actual: ${res.status}`);
        console.error(`       Reason: ${msg}`);
        if (res.stdout) console.error(`       Stdout: ${res.stdout.substring(0, 500)}`);
        if (res.stderr) console.error(`       Stderr: ${res.stderr}`);
        failed++;
    }
}

setup();
// 1. Exit Code: 0 (PASS)
fs.writeFileSync(path.join(TEST_DIR, 'safe.js'), 'console.log("Safe behavior");');
const res0 = runSentinel(['scan', 'safe.js', '--ci']);
assert('Exit Code 0 (Clean Code)', res0, 0, 'Clean code should return status 0');

setup();
// 2. Exit Code: 1 (SECURITY)
fs.writeFileSync(path.join(TEST_DIR, 'malware.js'), 'eval(Buffer.from("ZXZhbCgncnVuJyk=", "base64").toString());');
const res1 = runSentinel(['scan', 'malware.js', '--ci']);
assert('Exit Code 1 (Security Threat)', res1, 1, 'Malicious code should return status 1');

setup();
// 3. Exit Code: 2 (POLICY - Lockfile)
// Use a clearly invalid JSON for lockfile to trigger POLICY parse error
fs.writeFileSync(path.join(TEST_DIR, 'package-lock.json'), 'invalid_json_content');
const res2 = runSentinel(['scan', '.', '--ci']);
assert('Exit Code 2 (Policy Violation)', res2, 2, 'Policy violation should return status 2');

// 4. Command Availability
const resAudit = runSentinel(['audit', '--help']);
assert('Audit Command Availability', resAudit, 0, 'Audit command should be callable');

const resExplain = runSentinel(['explain', '--help']);
assert('Explain Command Availability', resExplain, 0, 'Explain command should be callable');

// 5. NPM Pack Integrity
try {
    process.stdout.write('[GATE] NPM Pack Viability Check             ... ');
    const packResult = execSync('npm pack --dry-run', { cwd: path.join(__dirname, '..'), encoding: 'utf-8' });
    if (packResult.includes('sentinel-security-engine')) {
        console.log('PASSED');
    } else {
        throw new Error('NPM pack did not identify the correct package name.');
    }
} catch (e) {
    console.log('FAILED');
    console.error(`       Reason: ${e.message}`);
    failed++;
}

console.log('─'.repeat(60));
if (failed === 0) {
    console.log('RESULT: STABLE. Ready for enterprise distribution.');
    process.exit(0);
} else {
    console.log(`RESULT: UNSTABLE. Blocking release due to ${failed} gate failures.`);
    process.exit(1);
}
