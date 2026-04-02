#!/usr/bin/env node
// CLI Function for Electron Integration
const { program } = require('commander');
const notifier = require('node-notifier');
const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Detection logic for packaged vs development environment
// If the command is called through a shim that uses node directly or the app's own executable
const isPackaged = (process.argv0 && process.argv0.toLowerCase().endsWith('sentinel.exe')) || 
                   process.execPath.toLowerCase().endsWith('sentinel.exe');

// Fallback search for the executable relative to the CLI script (for unpacked/portable installs)
const appExePath = isPackaged ? process.execPath : path.resolve(__dirname, '..', '..', '..', 'Sentinel.exe');
const isPackagedFinal = isPackaged || fs.existsSync(appExePath);

/**
 * Helper to send navigation intents to the running UI via the backend.
 */
async function postIntent(payload = { action: 'scan-all' }) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port: 3001,
            path: '/api/ui/intent',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, (res) => {
            if (res.statusCode === 200) resolve();
            else reject(new Error(`Server responded with status: ${res.statusCode}`));
        });
        
        req.on('error', (e) => reject(e));
        req.write(JSON.stringify(payload));
        req.end();
    });
}

/**
 * Manual scan logic - fetches PR data and scans it using backend libs.
 */
function performManualScan(repoId, githubName) {
    const db = require('../backend/lib/db');
    const gh = require('../backend/lib/gh_bridge');
    const { scanFile } = require('../backend/scanner/index');

    console.log(`🔍 Scanning open PRs for ${githubName}...`);
    const prs = gh.listPRs(githubName);
    let totalAlerts = 0;

    prs.forEach(pr => {
        console.log(`   - Checking PR #${pr.number}: ${pr.title}`);
        const diff = gh.getPRDiff(githubName, pr.number);
        if (diff) {
            const results = scanFile(`PR #${pr.number}.diff`, diff);
            if (results.alerts.length > 0) {
                totalAlerts += results.alerts.length;
                db.addScanLog(repoId, 'PR_THREAT', 10, `Threats in PR #${pr.number}`, results.alerts);
                db.updateRepoStatus(repoId, 'INFECTED');
                
                notifier.notify({
                    title: '🚨 Sentinel: Threat Detected!',
                    message: `PR #${pr.number} in ${githubName} looks dangerous.`,
                    sound: true
                });
            }
        }
    });

    if (totalAlerts === 0) {
        db.updateRepoStatus(repoId, 'SAFE');
        console.log("   ✅ No threats found.");
    } else {
        console.log(`   🚨 Found ${totalAlerts} potential threats!`);
    }
}

// ─── CLI COMMAND DEFINITIONS ───

program
    .version('1.0.0')
    .description('Sentinel Security CLI');

program
    .command('link <path> <github_full_name>')
    .description('Link a local project to Sentinel')
    .action((localPath, githubName) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const fullPath = path.resolve(localPath);
        console.log(`Linking repository at ${fullPath}...`);
        
        const info = gh.getRepoInfoLocal(fullPath);
        if (!info) {
            console.error("❌ Could not identify GitHub repository. Make sure 'gh' is authenticated and you are inside a git repo.");
            return;
        }

        const repoId = db.addRepository(fullPath, info.fullName);
        console.log(`✅ Success! Linked to ${info.fullName}`);
        
        // Initial scan
        performManualScan(repoId, info.fullName);
    });

program
    .command('list')
    .description('List all linked repositories')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        console.table(repos.map(r => ({
            ID: r.id,
            Name: r.github_full_name,
            Status: r.status,
            LastScan: r.last_scan_at
        })));
    });

program
    .command('scan')
    .description('Scan all linked repositories now')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        repos.forEach(repo => {
            performManualScan(repo.id, repo.github_full_name);
        });
    });

program
    .command('open')
    .description('Open Sentinel UI and navigate to specific view')
    .option('--repo <name>', 'Navigate to specific repository')
    .option('--pr <url>', 'Navigate to specific PR')
    .option('--scan-all', 'Trigger a global scan immediately on open')
    .action(async (options) => {
        const intentPayload = { 
            action: options.scanAll ? 'scan-all' : (options.pr ? 'pr' : 'repo'),
            target: options.pr || options.repo || null
        };

    try {
        if (isPackagedFinal) {
            console.log("📡 Sentinel Production detected. Launching app directly...");
            const exeToSpawn = isPackaged ? process.execPath : appExePath;
            
            spawn(exeToSpawn, ['.'], { 
                detached: true, 
                stdio: 'ignore' 
            });
            
            console.log("✅ Sentinel launched. Closing CLI.");
            process.exit(0); // Direct exit for production
        }

        // Development mode or backend intent logic
        await postIntent(intentPayload);
        console.log("✅ Sentinel UI navigated successfully via running backend.");
    } catch (e) {
        if (e.code === 'ECONNREFUSED' || e.message.includes('ECONNREFUSED')) {
            console.log("📡 Sentinel UI not running. Launching dev environment...");
            
            // In development, launch via npm run electron:dev
            const isWindows = process.platform === 'win32';
            const cmd = isWindows ? 'npm.cmd' : 'npm';
            const args = ['run', 'electron:dev'];
            const spawnCwd = path.resolve(__dirname, '..'); // 'ui' directory
            
            console.log(`📡 Launching via: ${cmd}`);
            
            const uiProcess = spawn(cmd, args, { 
                cwd: spawnCwd,
                detached: true, 
                stdio: 'ignore',
                windowsHide: true,
                shell: true 
            });

            uiProcess.unref();
            
            console.log("⏳ Waiting for UI to initialize (this may take a few seconds)...");
            
            let retries = 0;
            const retryInterval = setInterval(async () => {
                try {
                    await postIntent(intentPayload);
                    console.log("✅ Sentinel launched and navigated.");
                    clearInterval(retryInterval);
                    process.exit(0);
                } catch (err) {
                    retries++;
                    if (retries > 20) {
                        console.error("❌ Error: Sentinel UI did not become ready in time.");
                        clearInterval(retryInterval);
                        process.exit(1);
                    }
                }
            }, 1000);
        } else {
            console.error("❌ Communication error:", e.message);
            process.exit(1);
        }
    }
    });

function run(args = process.argv) {
    program.parse(args);
}

module.exports = { run };

if (require.main === module) {
    run();
}
