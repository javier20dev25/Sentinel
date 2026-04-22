/**
 * Sentinel GitHub Action Wrapper (Plug & Play)
 * 
 * This script is designed to be executed within a CI environment to trigger
 * a Sentinel scan with automated reporting and exit codes.
 */

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const TARGET = process.env.SENTINEL_TARGET || '.';
const SCAN_MODE = process.env.SENTINEL_MODE || 'fast'; // Default to fast for CI

console.log('🛡️  Sentinel CI Security Pipeline');
console.log('─'.repeat(40));
console.log(`Target: ${path.resolve(TARGET)}`);
console.log(`Mode: ${SCAN_MODE}`);

// Locate the Sentinel CLI entrypoint
// We search in a few common locations relative to the workspace
const possibleCliPaths = [
    path.join(__dirname, '..', 'src', 'ui', 'cli', 'index.js'),
    path.join(process.cwd(), 'node_modules', 'sentinel-local', 'src', 'ui', 'cli', 'index.js'),
    'sentinel' // Assume in PATH
];

let cliPath = null;
for (const p of possibleCliPaths) {
    if (fs.existsSync(p) || p === 'sentinel') {
        cliPath = p;
        break;
    }
}

if (!cliPath) {
    console.error('❌ Error: Sentinel CLI not found. Please ensure Sentinel is cloned or installed.');
    process.exit(1);
}

const args = ['scan', TARGET, `--mode=${SCAN_MODE === 'fast' ? 'local' : SCAN_MODE}`, '--ci'];
if (SCAN_MODE === 'fast') args.push('--fast');

const result = spawnSync('node', [cliPath, ...args], { stdio: 'inherit' });

if (result.status === 0) {
    console.log('\n✅ Sentinel: No threats found. Build passed.');
} else if (result.status === 1) {
    console.log('\n⚠️  Sentinel: Suspicious signals detected. Manual review recommended.');
} else {
    console.log('\n🛑 Sentinel: CRITICAL THREAT DETECTED. Blocking build.');
}

process.exit(result.status || 0);
