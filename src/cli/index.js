/**
 * Sentinel: CLI Manager
 */

const { program } = require('commander');
const notifier = require('node-notifier');
const http = require('http');
const { spawn } = require('child_process');

// Manual scan logic
function performManualScan(repoId, githubName) {
    const db = require('../ui/backend/lib/db');
    const gh = require('../ui/backend/lib/gh_bridge');
    const { scanFile } = require('../ui/backend/scanner/index');

    console.log(`Scanning open PRs for ${githubName}...`);
    const prs = gh.listPRs(githubName);
    let totalAlerts = 0;

    prs.forEach(pr => {
        console.log(`Checking PR #${pr.number}: ${pr.title}`);
        const diff = gh.getPRDiff(githubName, pr.number);
        if (diff) {
            const results = scanFile(`PR #${pr.number}.diff`, diff);
            if (results.alerts.length > 0) {
                totalAlerts += results.alerts.length;
                db.addScanLog(repoId, 'PR_THREAT', 10, `Threats in PR #${pr.number}`, results.alerts);
                db.updateRepoStatus(repoId, 'INFECTED');
                
                notifier.notify({
                    title: '🚨 Sentinel: Threat Detected!',
                    message: `PR #${pr.number} in ${githubName} looks dangerous. Check the logs.`,
                    sound: true,
                    wait: true
                });
            }
        }
    });

    if (totalAlerts === 0) {
        db.updateRepoStatus(repoId, 'SAFE');
        console.log("  ✅ No threats found.");
    } else {
        console.log(`  🚨 Found ${totalAlerts} potential threats!`);
    }
}

// CLI Commands
program
    .version('1.0.0')
    .description('Sentinel Security CLI');

program
    .command('link <path> <github_full_name>')
    .description('Link a local project to Sentinel')
    .action((localPath, githubName) => {
        const db = require('../ui/backend/lib/db');
        const gh = require('../ui/backend/lib/gh_bridge');
        const { resolve } = require('path');
        const fullPath = resolve(localPath);
        console.log(`Linking repo at ${fullPath}...`);
        
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
        const db = require('../ui/backend/lib/db');
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
        const db = require('../ui/backend/lib/db');
        const repos = db.getRepositories();
        repos.forEach(repo => {
            performManualScan(repo.id, repo.github_full_name);
        });
    });

// CLI open UI command -> Send Intent
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

        const postIntent = () => {
            return new Promise((resolve, reject) => {
                const req = http.request({
                    hostname: '127.0.0.1',
                    port: 3001,
                    path: '/api/ui/intent',
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                }, (res) => {
                    resolve(res.statusCode);
                });
                req.on('error', reject);
                req.write(JSON.stringify(intentPayload));
                req.end();
            });
        };

        try {
            await postIntent();
            console.log("✅ Sentinel UI navigated successfully via SSE intent.");
        } catch (e) {
            if (e.code === 'ECONNREFUSED') {
                console.log("📡 Sentinel UI not running. Launching app...");
                
                // Spawn UI detached
                const isWindows = process.platform === 'win32';
                const cmd = isWindows ? 'cmd.exe' : 'npm';
                const args = isWindows ? ['/c', 'npm', 'run', 'ui'] : ['run', 'ui'];
                
                spawn(cmd, args, { 
                    cwd: require('path').resolve(__dirname, '../../'),
                    detached: true, 
                    stdio: 'ignore',
                    windowsHide: true
                }).unref();
                
                console.log("⏳ Starting background server & UI, please wait...");
                
                // Retry intent continuously for up to 15 seconds
                let retries = 0;
                const retryInterval = setInterval(async () => {
                    try {
                        await postIntent();
                        console.log("✅ Application launched and navigated.");
                        clearInterval(retryInterval);
                    } catch (err) {
                        retries++;
                        if (retries > 15) {
                            console.error("❌ Failed to reach UI within 15 seconds.");
                            clearInterval(retryInterval);
                        }
                    }
                }, 1000);
            } else {
                console.error("❌ Error sending intent:", e.message);
            }
        }
    });

program.parse(process.argv);
