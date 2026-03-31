/**
 * Sentinel: Global Startup Manager (HARDENED)
 * Runs the API server and the background polling service simultaneously.
 * 
 * SECURITY: spawn uses shell:false (default). No command string interpolation.
 * All arguments passed as arrays.
 * 
 * Audit: VULN-001 remediated — spawn with shell:true replaced.
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');

function runProcess(name, command, args, cwd) {
    // SECURITY: shell is NOT set — defaults to false
    // Arguments are passed as an array, never interpolated into a string
    const proc = spawn(command, args, { cwd });

    proc.stdout.on('data', (data) => {
        console.log(`[${name}] ${data.toString().trim()}`);
    });

    proc.stderr.on('data', (data) => {
        console.error(`[${name} ERROR] ${data.toString().trim()}`);
    });

    proc.on('close', (code) => {
        console.log(`[${name}] process exited with code ${code}`);
    });

    return proc;
}

console.log("🛡️ Starting Sentinel Security Suite...");

// 1. Start Database/API Server
runProcess('API', 'node', [path.join(__dirname, 'ui', 'backend', 'server', 'index.js')], __dirname);

// 2. Start Background Polling Service
runProcess('SERVICE', 'node', [path.join(__dirname, 'ui', 'backend', 'services', 'polling.js')], __dirname);

// 3. Start Frontend UI (Headless for App Mode)
// NOTE: npm requires shell on Windows to resolve npm.cmd, so we use process.platform check
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
runProcess('UI', npmCmd, ['run', 'dev'], path.join(__dirname, 'ui'));
