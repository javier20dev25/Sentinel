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
                shell: false 
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

// ─── sentinel sandbox --sync [--auto] ───
program
    .command('sandbox')
    .description('Manage the Sentinel Sandbox Guardian for linked repositories')
    .option('--sync', 'Install or update the sandbox workflow in the linked repo')
    .option('--auto', 'Auto-install via git push (requires contents:write). Default: manual copy mode')
    .option('--status', 'Show sandbox status for all linked repos')
    .action(async (options) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const fs = require('fs');

        if (options.status || (!options.sync && !options.auto)) {
            // Show status table
            const repos = db.getRepositories();
            if (repos.length === 0) {
                console.log('No repositories linked. Use: sentinel link <path> <owner/repo>');
                return;
            }
            console.log('\n🛡️  Sentinel Sandbox Status\n');
            repos.forEach(repo => {
                const installed = repo.local_path ? gh.checkSandboxInstalled(repo.local_path) : { installed: false };
                const run = gh.getLatestSandboxRun(repo.github_full_name);
                const statusIcon = !installed.installed ? '⚪ Not configured' :
                    !run ? '🟡 Installed, no runs yet' :
                    run.conclusion === 'success' ? '🟢 Clean' :
                    run.conclusion === 'failure' ? '🔴 Threat detected' : '🔵 Running';
                console.log(`  ${repo.github_full_name}`);
                console.log(`  └─ ${statusIcon}${run?.html_url ? `  → ${run.html_url}` : ''}`);
                console.log('');
            });
            return;
        }

        if (options.sync) {
            const repos = db.getRepositories().filter(r => r.local_path);
            if (repos.length === 0) {
                console.error('❌ No repositories with a local path found. Link one first: sentinel link <path> <owner/repo>');
                process.exit(1);
            }

            // Use the first repo (or could add --repo option in future)
            const repo = repos[0];
            console.log(`\n🛡️  Installing Sandbox Guardian for: ${repo.github_full_name}`);

            if (options.auto) {
                console.log('⚠️  Auto mode: This will commit and push to your repository.');
                console.log('   Requires: git push access + gh CLI with contents:write\n');
                const result = gh.pushSandboxConfig(repo.local_path);
                if (result.success) {
                    db.setSandboxConsent(repo.id, true);
                    db.setSandboxVersion(repo.id, '1.0');
                    console.log('✅ Sandbox workflow installed and pushed!');
                    console.log(`   File: ${result.path}`);
                } else {
                    console.error('❌ Auto-install failed:', result.error);
                    console.log('   Try manual mode (without --auto) instead.');
                    process.exit(1);
                }
            } else {
                // Manual mode: show the path and content
                const templateContent = gh.getSandboxTemplateContent();
                const destPath = path.join(repo.local_path, '.github', 'workflows', 'sentinel-sandbox.yml');
                const outputFile = path.join(process.cwd(), 'sentinel-sandbox.yml');
                fs.writeFileSync(outputFile, templateContent, 'utf-8');

                console.log('✅ Template saved to your current directory:');
                console.log(`   ${outputFile}\n`);
                console.log('📋 Next steps:');
                console.log(`   1. Copy it to: ${destPath}`);
                console.log('   2. git add .github/workflows/sentinel-sandbox.yml');
                console.log('   3. git commit -m "chore: add Sentinel sandbox workflow"');
                console.log('   4. git push');
                console.log('\nOr use --auto to let Sentinel do it automatically.\n');
            }
        }
    });

// ─── sentinel analyze --local ───
program
    .command('analyze')
    .description('Analyze local changes before committing')
    .option('--local', 'Scan staged and unstaged git diff for threats')
    .option('--exclude-protected', 'Automatically unstage (git reset HEAD) any protected files before scanning/committing')
    .option('--force', 'Bypass protected files block')
    .action(async (options) => {
        const gh = require('../backend/lib/gh_bridge');
        const db = require('../backend/lib/db');
        const { scanFile } = require('../backend/scanner/index');
        const { execFileSync } = require('child_process');
        const path = require('path');
        const cwd = process.cwd();

        console.log('\n🔍 Sentinel: Analyzing local changes...\n');

        // --- Protected Files Interception ---
        const repos = db.getRepositories();
        // Match repo by local path. Use path.resolve for safety.
        const repo = repos.find(r => r.local_path && path.resolve(r.local_path) === path.resolve(cwd));
        
        let protectedBlocked = false;
        if (repo) {
            try {
                const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf-8', timeout: 5000 });
                const changedFiles = statusOutput.split('\n').filter(l => l.trim().length > 0).map(l => l.substring(3).trim());
                const protectedList = db.getProtectedFiles(repo.id).map(p => path.normalize(p.file_path));
                
                const violations = [];
                for (const file of changedFiles) {
                    const normFile = path.normalize(file);
                    const isProtected = protectedList.some(p => normFile === p || normFile.startsWith(p + path.sep));
                    if (isProtected) violations.push(file);
                }

                if (violations.length > 0) {
                    console.log(`\n⚠️  PROTECTED FILES DETECTED:`);
                    violations.forEach(v => console.log(`   - ${v}`));
                    
                    if (options.excludeProtected) {
                        console.log('\n✅ --exclude-protected flag passed. Unstaging protected files...');
                        violations.forEach(v => {
                            try {
                                execFileSync('git', ['reset', 'HEAD', v], { cwd, timeout: 5000 });
                                console.log(`   Unstaged: ${v}`);
                            } catch (e) {
                                console.log(`   Failed to unstage: ${v}`);
                            }
                        });
                    } else if (!options.force) {
                        console.log('\n🚫 BLOCKED: You are attempting to commit protected files.');
                        console.log('   Use the Sentinel UI to manage this, OR use one of these flags:');
                        console.log('   --exclude-protected   (Removes them from the commit automatically)');
                        console.log('   --force               (Bypasses this block and scans/commits anyway)\n');
                        process.exit(1);
                    } else {
                        console.log('\n⚠️  --force flag passed. Bypassing protected files block...\n');
                    }
                }
            } catch (e) {
                // Ignore git errors if not a git repo
            }
        }

        const diff = gh.getLocalDiff(cwd);
        if (!diff) {
            console.log('✅ No local changes detected. Working tree is clean.');
            return;
        }

        const linesCount = diff.split('\n').length;
        console.log(`   Scanning ${linesCount} diff lines...`);

        const results = scanFile('local.diff', diff);
        const criticals = results.alerts.filter(a => (a.riskLevel || 0) >= 8);
        const warnings  = results.alerts.filter(a => (a.riskLevel || 0) >= 4 && (a.riskLevel || 0) < 8);

        if (results.alerts.length === 0) {
            console.log('✅ No threats detected. Safe to commit.\n');
        } else {
            if (criticals.length > 0) {
                console.log(`🔴 BLOCKED: ${criticals.length} critical threat(s) detected!\n`);
                criticals.forEach(a => {
                    console.log(`   [CRITICAL] ${a.ruleName || 'THREAT'}: ${a.description || 'No description'}`);
                });
            }
            if (warnings.length > 0) {
                console.log(`\n⚠️  ${warnings.length} warning(s):\n`);
                warnings.forEach(a => {
                    console.log(`   [WARN] ${a.ruleName || 'FINDING'}: ${a.description || 'No description'}`);
                });
            }
            if (criticals.length > 0) {
                console.log('\n❌ Push is NOT recommended until critical issues are resolved.');
                process.exit(1);
            } else {
                console.log('\n✓ No critical threats. Proceed with caution.\n');
            }
        }
    });

// ─── sentinel status ───
program
    .command('status')
    .description('Show security status of all linked repositories')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        if (repos.length === 0) {
            console.log('No repositories linked yet. Use: sentinel link <path> <owner/repo>');
            return;
        }
        console.log('\n🛡️  Sentinel — Repository Status\n');
        repos.forEach(repo => {
            const icon = repo.status === 'SAFE' ? '🟢' : repo.status === 'INFECTED' ? '🔴' : '🟡';
            console.log(`  ${icon} ${repo.github_full_name}`);
            console.log(`     Status: ${repo.status}  |  Last scan: ${repo.last_scan_at || 'Never'}`);
            console.log('');
        });
    });

function run(args = process.argv) {
    program.parse(args);
}

module.exports = { run };

if (require.main === module) {
    run();
}
