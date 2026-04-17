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

/**
 * Consistent Response Format for AI Agents
 */
function respondAgent(success, data, error = null) {
    if (program.opts().json) {
        process.stdout.write(JSON.stringify({
            success,
            data,
            error: error ? String(error) : null
        }, null, 2) + '\n');
        process.exit(success ? 0 : 1);
    }
}

// Detection logic for packaged vs development environment
const isPackaged = (process.argv0 && process.argv0.toLowerCase().endsWith('sentinel.exe')) || 
                   process.execPath.toLowerCase().endsWith('sentinel.exe');

// Fallback search for the executable relative to the CLI script (for unpacked/portable installs)
const appExePath = isPackaged ? process.execPath : path.resolve(__dirname, '..', '..', '..', 'Sentinel.exe');
const isPackagedFinal = isPackaged || fs.existsSync(appExePath);

/**
 * Generates a professional Markdown report for GitHub visibility.
 */
function generateMarkdownReport(githubName, prNumber, alerts) {
    let report = `## 🛡️ Sentinel: Security Threat Detected in PR #${prNumber}\n\n`;
    report += `**Repository:** ${githubName}\n`;
    report += `**Status:** 🚨 THREAT FOUND\n\n`;
    report += `Sentinel has identified potential security risks in this proposal. Transparency is key to maintaining repository integrity.\n\n`;
    
    report += `| Level | Severity | Rule | Description |\n`;
    report += `| :--- | :--- | :--- | :--- |\n`;
    
    alerts.forEach(a => {
        const severityStr = a.riskLevel >= 9 ? '🔥 CRITICAL' : (a.riskLevel >= 7 ? '🔴 HIGH' : '⚠️ MEDIUM');
        report += `| ${a.riskLevel}/10 | ${severityStr} | **${a.ruleName}** | ${a.description} |\n`;
    });
    
    report += `\n### 🔍 Evidence\n`;
    alerts.forEach(a => {
        report += `#### Rule: ${a.ruleName}\n`;
        report += `**Snippet:**\n\`\`\`javascript\n${a.evidence}\n\`\`\`\n\n`;
    });
    
    report += `\n---\n*Report generated automatically by Sentinel Security Core.*`;
    return report;
}

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

    const isCI = process.env.GITHUB_ACTIONS === 'true';
    const summaryPath = process.env.GITHUB_STEP_SUMMARY;

    console.log(`🔍 Scanning for threats in ${githubName}...`);
    let totalAlerts = 0;
    
    // Attempt 1: Fetch and scan PRs via API
    const prs = gh.listPRs(githubName);
    
    if (prs.length > 0) {
        console.log(`🔎 Found ${prs.length} open PR(s) to analyze via API.`);
        prs.forEach(pr => {
            if (!program.opts().json) console.log(`   - Checking PR #${pr.number}: ${pr.title}`);
            try {
                const diff = gh.getPRDiff(githubName, pr.number);
                if (diff) {
                    const results = scanFile(`PR #${pr.number}.diff`, diff);
                    if (results.alerts.length > 0) {
                        processResults(results, `PR #${pr.number}`, pr.number);
                    }
                }
            } catch (e) {
                console.error(`   ⚠️  Error scanning PR #${pr.number}: ${e.message}`);
                if (e.message.includes('406')) {
                    console.error("      Note: Standard GitHub CLI diffs are limited to 300 files. High-volume PRs should be reviewed manually.");
                }
            }
        });
    } else if (isCI) {
        // Attempt 2: CI Fallback - Scan all local JS files in the workspace
        console.log("⚠️ [Sentinel CI] No PRs detected via API. Performing deep local scan of workspace...");
        const glob = require('glob');
        const files = glob.sync('**/*.{js,ts,jsx,tsx}', { 
            ignore: ['node_modules/**', 'dist/**', 'build/**'] 
        });
        
        files.forEach(file => {
            const content = fs.readFileSync(file, 'utf8');
            const results = scanFile(file, content);
            if (results.alerts.length > 0) {
                processResults(results, file);
            }
        });
    }

    function processResults(results, sourceName, prNumber = null) {
        totalAlerts += results.alerts.length;
        db.addScanLog(repoId, 'THREAT_DETECTED', 10, `Threats in ${sourceName}`, results.alerts);
        db.updateRepoStatus(repoId, 'INFECTED');
        
        // Local Notification (ignored in CI)
        safeNotify({
            title: '🚨 Sentinel: Threat Detected!',
            message: `${sourceName} looks dangerous.`,
            sound: true
        });

        // PR Reporting (if we have a PR number)
        if (prNumber) {
            const mdReport = generateMarkdownReport(githubName, prNumber, results.alerts);
            gh.postPRComment(githubName, prNumber, mdReport);
        }

        // CI Step Summary reporting
        if (isCI && summaryPath) {
            const mdSummary = `### 🚨 Threat Evidence in \`${sourceName}\`\n` + 
                            results.alerts.map(a => `- **[${a.riskLevel}/10] ${a.ruleName}**: ${a.description}`).join('\n') + 
                            `\n\n\`\`\`javascript\n${results.alerts[0].evidence}\n\`\`\`\n`;
            fs.appendFileSync(summaryPath, mdSummary + '\n\n');
        }
    }

    if (totalAlerts === 0) {
        db.updateRepoStatus(repoId, 'SAFE');
        console.log("   ✅ No threats found.");
    } else {
        console.log(`   🚨 Found ${totalAlerts} potential threats!`);
        // In CI, if we find threats, we should fail the job to block the merge effectively
        if (isCI) {
            console.error("❌ Blocking build due to security threats.");
            process.exit(1);
        }
    }
}

// ─── CLI COMMAND DEFINITIONS ───

program
    .version('1.0.0')
    .description('Sentinel Security CLI')
    .option('--json', 'Output structured JSON for AI and automation');

program
    .command('link <path> <github_full_name>')
    .description('Link a local project to Sentinel')
    .action((localPath, githubName) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const fullPath = path.resolve(localPath);
        
        if (!program.opts().json) console.log(`Linking repository at ${fullPath}...`);
        
        const info = gh.getRepoInfoLocal(fullPath);
        if (!info) {
            if (program.opts().json) respondAgent(false, null, "Could not identify GitHub repository. Make sure 'gh' is authenticated.");
            console.error("❌ Could not identify GitHub repository. Make sure 'gh' is authenticated and you are inside a git repo.");
            return;
        }

        const repoId = db.addRepository(fullPath, info.fullName);
        if (!program.opts().json) console.log(`✅ Success! Linked to ${info.fullName}`);
        
        if (program.opts().json) respondAgent(true, { id: repoId, fullName: info.fullName });
        
        performManualScan(repoId, info.fullName);
    });

program
    .command('list')
    .description('List all linked repositories')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        
        const data = repos.map(r => ({
            id: r.id,
            fullName: r.github_full_name,
            status: r.status,
            lastScan: r.last_scan_at
        }));

        if (program.opts().json) respondAgent(true, data);

        console.table(data);
    });

program
    .command('scan')
    .description('Scan all linked repositories now')
    .action(() => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        let repos = db.getRepositories();
        
        // CI RESILIENCE: If running in GitHub Actions and no repos are linked, auto-link current dir
        if (repos.length === 0 && process.env.GITHUB_ACTIONS === 'true') {
            console.log("🛡️ [Sentinel CI] No linked repositories found. Auto-linking current workspace...");
            const info = gh.getRepoInfoLocal(process.cwd());
            if (info) {
                const repoId = db.addRepository(process.cwd(), info.fullName);
                repos = [db.getRepositoryById(repoId)];
            } else {
                console.error("❌ [Sentinel CI] Could not identify GitHub repository from current workspace.");
            }
        }

        repos.forEach(repo => {
            performManualScan(repo.id, repo.github_full_name);
        });

        if (program.opts().json) respondAgent(true, { scanned: repos.length });
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
                shell: false 
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
            
            const results = repos.map(repo => {
                const installed = repo.local_path ? gh.checkSandboxInstalled(repo.local_path) : { installed: false };
                const run = gh.getLatestSandboxRun(repo.github_full_name);
                return {
                    fullName: repo.github_full_name,
                    installed: installed.installed,
                    version: installed.version,
                    latestRun: run
                };
            });

            if (program.opts().json) respondAgent(true, results);

            if (repos.length === 0) {
                console.log('No repositories linked. Use: sentinel link <path> <owner/repo>');
                return;
            }
            console.log('\n🛡️  Sentinel Sandbox Status\n');
            results.forEach(res => {
                const statusIcon = !res.installed ? '⚪ Not configured' :
                    !res.latestRun ? '🟡 Installed, no runs yet' :
                    res.latestRun.conclusion === 'success' ? '🟢 Clean' :
                    res.latestRun.conclusion === 'failure' ? '🔴 Threat detected' : '🔵 Running';
                console.log(`  ${res.fullName}`);
                console.log(`  └─ ${statusIcon}${res.latestRun?.html_url ? `  → ${res.latestRun.html_url}` : ''}`);
                console.log('');
            });
            return;
        }

        if (options.sync) {
            const repos = db.getRepositories().filter(r => r.local_path);
            if (repos.length === 0) {
                if (program.opts().json) respondAgent(false, null, 'No repositories with a local path found.');
                console.error('❌ No repositories with a local path found. Link one first: sentinel link <path> <owner/repo>');
                process.exit(1);
            }

            // Use the first repo (or could add --repo option in future)
            const repo = repos[0];
            if (!program.opts().json) console.log(`\n🛡️  Installing Sandbox Guardian for: ${repo.github_full_name}`);

            if (options.auto) {
                if (!program.opts().json) {
                    console.log('⚠️  Auto mode: This will commit and push to your repository.');
                    console.log('   Requires: git push access + gh CLI with contents:write\n');
                }
                const result = gh.pushSandboxConfig(repo.local_path);
                if (result.success) {
                    db.setSandboxConsent(repo.id, true);
                    db.setSandboxVersion(repo.id, '1.0');
                    if (program.opts().json) respondAgent(true, { installed: true, pushed: true, path: result.path });
                    console.log('✅ Sandbox workflow installed and pushed!');
                } else {
                    if (program.opts().json) respondAgent(false, null, result.error);
                    console.error('❌ Auto-install failed:', result.error);
                    process.exit(1);
                }
            } else {
                // Manual mode
                const templateContent = gh.getSandboxTemplateContent();
                const outputFile = path.join(process.cwd(), 'sentinel-sandbox.yml');
                fs.writeFileSync(outputFile, templateContent, 'utf-8');

                if (program.opts().json) respondAgent(true, { installed: true, pushed: false, outputFile });
                
                console.log('✅ Template saved to your current directory:');
                console.log(`   ${outputFile}`);
            }
        }
    });

// ─── sentinel packs load <file> ───
program
    .command('packs')
    .description('Manage Config Packs for the current repository')
    .argument('<action>', 'Action to perform (e.g. load)')
    .argument('[file]', 'Path to the config pack file')
    .action((action, file) => {
        if (action !== 'load' || !file) {
            console.error('❌ Usage: sentinel packs load <file>');
            process.exit(1);
        }

        const db = require('../backend/lib/db');
        const fs = require('fs');
        const path = require('path');
        const crypto = require('crypto');

        const cwd = process.cwd();
        const repos = db.getRepositories();
        const repo = repos.find(r => r.local_path && path.resolve(r.local_path) === path.resolve(cwd));

        if (!repo) {
            console.error('❌ No linked repository found for the current directory.');
            process.exit(1);
        }

        try {
            const packContent = fs.readFileSync(path.resolve(file), 'utf8');
            const packData = JSON.parse(packContent);

            let isOfficial = false;
            if (packData._signature) {
                try {
                    const SENTINEL_LAB_PUB_KEY = "MCowBQYDK2VwAyEAi43t85W8oYdD+F570RkG2q4Oa0R1OEvnmb89N2B43rU=";
                    const dataToSign = {
                        metadata: packData.metadata,
                        config: packData.config
                    };
                    const payloadBuffer = Buffer.from(JSON.stringify(dataToSign));
                    const pubKey = crypto.createPublicKey({ key: Buffer.from(SENTINEL_LAB_PUB_KEY, 'base64'), format: 'der', type: 'spki' });
                    const isValid = crypto.verify(null, payloadBuffer, pubKey, Buffer.from(packData._signature, 'base64'));
                    if (isValid) isOfficial = true;
                } catch (e) {
                    // ignore
                }
            }

            console.log('\n📦 Loading Config Pack...');
            console.log(`   Name: ${packData.metadata?.name || 'Unknown'}`);
            console.log(`   Official: ${isOfficial ? '✅ Yes' : '❌ No'}`);

            db.installPack(repo.id, packData, isOfficial);
            if (program.opts().json) respondAgent(true, { installed: true, name: packData.metadata?.name });
            console.log('\n✅ Pack successfully loaded into the repository config!');

        } catch (e) {
            if (program.opts().json) respondAgent(false, null, e.message);
            console.error('❌ Error loading pack:', e.message);
            process.exit(1);
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

        if (program.opts().json) {
            respondAgent(true, {
                alerts: results.alerts,
                isClean: results.alerts.length === 0,
                criticalCount: results.alerts.filter(a => (a.riskLevel || 0) >= 8).length
            });
        }

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
        
        if (program.opts().json) respondAgent(true, repos);

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
