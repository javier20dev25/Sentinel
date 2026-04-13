#!/usr/bin/env node
// CLI Function for Electron Integration
const { program } = require('commander');
const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Lazy-load node-notifier (may not be available in packaged mode)
let notifier = null;
try { notifier = require('node-notifier'); } catch (_) {}
function safeNotify(opts) { try { if (notifier) notifier.notify(opts); } catch (_) {} }

// Detection logic for packaged vs development environment
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
                
                safeNotify({
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
    .command('hook <eventName>')
    .description('Sentinel Git Hook Entrypoint')
    .option('--reverse', 'Dry-run or securely revert code state instead of blocking')
    .action((eventName, options) => {
        if (eventName === 'pre-push') {
            console.log("🛡️ [Sentinel] Analyzing outbound commits for security threats...");
            try {
                const { execSync } = require('child_process');
                const { scanFile } = require('../backend/scanner/index');
                
                // Diff of what is about to be pushed compared to remote tracking branch
                let diff = '';
                try {
                    diff = execSync('git diff @{u}..HEAD', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
                } catch (e) {
                    // No upstream or other error: fallback to full staged/unpushed diff check via HEAD
                    try {
                        diff = execSync('git diff HEAD~1..HEAD', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
                    } catch(e2) {
                        diff = '';
                    }
                }
                
                if (diff.trim() === '') {
                    console.log("🛡️ [Sentinel] No diff found to scan. Proceeding...");
                    process.exit(0);
                }
                
                const results = scanFile('pre_push_commit.diff', diff);
                
                if (results.alerts.length > 0) {
                    safeNotify({
                        title: '🚨 Sentinel: Push Blocked!',
                        message: `Malicious code detected in outbound commits.`,
                        sound: true
                    });
                    
                    console.error("\\n🚨 [SENTINEL ALERT] Push structurally halted! Malicious code detected in outbound commits:");
                    results.alerts.forEach(alert => {
                        console.error(`  - [${alert.riskLevel}] ${alert.ruleName}: ${alert.description}`);
                    });
                    
                    if (options.reverse) {
                        console.log("\\n♻️ [Reverse Analyzer] --reverse flag enabled. Dry-run noted. State maintained.");
                        console.log("   To securely revert the malicious commit, run: git reset --soft HEAD~1");
                        process.exit(0); // In reverse dry-run, we allow it or just exit 0 so to not block if it's a dry run
                    } else {
                        console.error("\\n❌ Strict enforcement: Push blocked.");
                        console.error("   Use 'sentinel hook pre-push --reverse' for dry-run analysis.");
                        process.exit(1);
                    }
                } else {
                    console.log("✅ [Sentinel] Code changes are clean. Push allowed.");
                    process.exit(0);
                }
            } catch (err) {
                console.error("🛡️ [Sentinel] Hook error:", err.message);
                process.exit(0); // Fail-open so we don't break git completely on unrelated errors
            }
        }
    });

// ─── Command: Open ──────────────────────────────────────────────────────────

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
            const exeToSpawn = isPackaged ? process.execPath : appExePath;
            
            spawn(exeToSpawn, ['.'], { 
                detached: true, 
                stdio: 'ignore' 
            });
            process.exit(0);
        }

        await postIntent(intentPayload);
        console.log("✅ Sentinel UI navigated successfully via running backend.");
    } catch (e) {
        if (e.code === 'ECONNREFUSED' || e.message.includes('ECONNREFUSED')) {
            const isWindows = process.platform === 'win32';
            const cmd = isWindows ? 'npm.cmd' : 'npm';
            const args = ['run', 'electron:dev'];
            const spawnCwd = path.resolve(__dirname, '..'); 
            
            const uiProcess = spawn(`${cmd} ${args.join(' ')}`, { 
                cwd: spawnCwd,
                detached: true, 
                stdio: 'ignore',
                windowsHide: true,
                shell: true 
            });

            uiProcess.unref();
            let retries = 0;
            const retryInterval = setInterval(async () => {
                try {
                    await postIntent(intentPayload);
                    clearInterval(retryInterval);
                    process.exit(0);
                } catch (err) {
                    retries++;
                    if (retries > 20) {
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

// ─── Command: Sandbox (Sentinel 3.0) ────────────────────────────────────────

const sandbox = program
    .command('sandbox')
    .description('Manage and monitor dynamic sandbox analysis in GitHub Actions');

sandbox
    .command('generate')
    .description('Generate the sentinel-sandbox.yml workflow template')
    .action(() => {
        const ci = require('../backend/lib/ci_sandbox');
        const result = ci.generateWorkflowTemplate();
        if (result.success) {
            console.log("\n--- SENTINEL SANDBOX WORKFLOW TEMPLATE ---");
            console.log(result.workflowContent);
            console.log("\n--- INSTRUCTIONS ---");
            result.instructions.forEach(ins => console.log(ins));
        } else {
            console.error(`❌ Error: ${result.error}`);
        }
    });

sandbox
    .command('trigger <repo> [branch]')
    .description('Trigger a dynamic sandbox analysis run')
    .option('--async', 'Do not wait for completion (return runId immediately)')
    .action(async (repo, branch, options) => {
        const ci = require('../backend/lib/ci_sandbox');
        const targetBranch = branch || 'main';
        
        console.log(`🚀 Triggering sandbox analysis for ${repo} on branch ${targetBranch}...`);
        const result = await ci.triggerSandboxRun(repo, targetBranch);

        if (!result.success) {
            console.error(`❌ Failed to trigger: ${result.error}`);
            return;
        }

        console.log(`✅ Run triggered! ID: ${result.runId}`);
        console.log(`🔗 URL: ${result.url}`);

        if (options.async) {
            console.log("Exiting (async mode). Use 'sentinel sandbox status' to check progress.");
            return;
        }

        // Wait for completion (default mode)
        console.log("⏳ Waiting for analysis to complete (this may take a few minutes)...");
        
        let lastStatus = '';
        const run = await ci.waitForSandboxRun(repo, result.runId, null, 900000, (s) => {
            if (s.status !== lastStatus) {
                console.log(`   [STATUS] ${s.status}${s.conclusion ? ` (${s.conclusion})` : ''}`);
                lastStatus = s.status;
            }
        });

        if (run.concluded && run.conclusion === 'success') {
            console.log("✅ Analysis completed successfully. Fetching results...");
            // Automatically analyze after successful completion
            handleSandboxAnalysis(repo, result.runId);
        } else {
            console.error(`❌ Analysis ended with conclusion: ${run.conclusion || 'failed'}`);
            if (run.timedOut) console.error("   Reason: Timeout reached.");
        }
    });

sandbox
    .command('status <repo> <runId>')
    .description('Check the status of a sandbox run')
    .action((repo, runId) => {
        const ci = require('../backend/lib/ci_sandbox');
        const status = ci.getSandboxRunStatus(repo, parseInt(runId));
        if (status.error) {
            console.error(`❌ Error: ${status.error}`);
        } else {
            console.log(`Run status: ${status.status}`);
            if (status.conclusion) console.log(`Conclusion: ${status.conclusion}`);
            console.log(`URL: ${status.url}`);
        }
    });

sandbox
    .command('analyze <repo> <runId>')
    .description('Download and analyze telemetry from a completed run')
    .action(async (repo, runId) => {
        handleSandboxAnalysis(repo, parseInt(runId));
    });

async function handleSandboxAnalysis(repo, runId) {
    const ci = require('../backend/lib/ci_sandbox');
    console.log(`📥 Downloading artifacts for run #${runId}...`);
    
    const download = ci.downloadSandboxArtifacts(repo, runId);
    if (!download.success) {
        console.error(`❌ Download failed: ${download.error}`);
        return;
    }

    console.log(`🔍 Analyzing telemetry...`);
    const analysis = ci.analyzeTelemetry(download.tempDir, repo);
    
    if (analysis.threats.length === 0) {
        console.log("\n✅ [SAFE] No malicious behavior detected in sandbox simulation.");
    } else {
        console.log(`\n🚨 FOUND ${analysis.threats.length} SUSPICIOUS BEHAVIORS IN SANDBOX:`);
        analysis.threats.forEach(t => {
            console.log(`\n[${t.severity}] ${t.type}`);
            console.log(`Message: ${t.message}`);
            console.log(`Evidence: ${t.evidence.substring(0, 150)}...`);
        });
        console.log(`\nRisk Score: ${analysis.riskScore.toFixed(1)}/10`);
        
        console.log("\n[RECOMMENDATION]");
        if (analysis.riskScore >= 7) {
            console.log("The analysis indicates a highly compromised installation environment.");
            console.log("1. DO NOT install or merge this version.");
            console.log("2. Verify the source registry in your .npmrc file.");
        } else {
            console.log("Proceed with caution. Audit the detected behaviors manually.");
        }
    }

    ci.cleanupTempDir(download.tempDir);
}

function run(args = process.argv) {
    program.parse(args);
}

module.exports = { run };

if (require.main === module) {
    run();
}
