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
 * Normalizes paths for reliable comparison on Windows/Unix.
 * Handles both relative paths (from git status) and absolute paths (from DB).
 */
function normalizePath(p) {
    if (!p) return '';
    // Use normalize (NOT resolve) to avoid converting relative paths to absolute.
    // This preserves 'keys/file.txt' as 'keys/file.txt' instead of 'C:/Users/.../keys/file.txt'.
    return path.normalize(p).toLowerCase().replace(/\\/g, '/');
}

/**
 * Normalizes an absolute path (for repo local_path comparison).
 */
function normalizeAbsPath(p) {
    if (!p) return '';
    return path.resolve(p).toLowerCase().replace(/\\/g, '/');
}

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
        
        const info = gh.getRepoInfoLocal(fullPath);
        if (!info) {
            if (program.opts().json) respondAgent(false, null, "Could not identify GitHub repository. Make sure 'gh' is authenticated.");
            console.error("❌ Could not identify GitHub repository. Make sure 'gh' is authenticated and you are inside a git repo.");
            return;
        }

        let repoId = db.addRepository(fullPath, info.fullName);
        
        // Update path if it changed
        const existing = db.getRepositoryById(repoId);
        if (normalizeAbsPath(existing.local_path) !== normalizeAbsPath(fullPath)) {
            db.updateRepoPath(repoId, fullPath);
        }

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

/**
 * Shared logic for local analysis (used by 'analyze' and 'hook').
 * Returns { success, alerts, violations, repo }
 */
function performLocalAnalysis(options = {}) {
    const gh = require('../backend/lib/gh_bridge');
    const db = require('../backend/lib/db');
    const { scanFile } = require('../backend/scanner/index');
    const { execFileSync } = require('child_process');
    const cwd = process.cwd();

    const repos = db.getRepositories();
    const repo = repos.find(r => r.local_path && normalizeAbsPath(r.local_path) === normalizeAbsPath(cwd));
    
    let violations = [];
    if (repo) {
        try {
            // --- Source 1: Staged but uncommitted files (git status) ---
            const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf-8', timeout: 5000 });
            const changedFiles = statusOutput.split('\n')
                .filter(l => l.trim().length > 0)
                .map(l => ({ status: l.substring(0, 2), file: l.substring(3).trim() }));
            
            // --- Source 2: Committed but unpushed files (for prepush/hook mode) ---
            // git status becomes empty after commit, so we also check what's about to be pushed.
            let unpushedFiles = [];
            if (options.isHook) {
                try {
                    const unpushedOutput = execFileSync('git', ['diff', '--name-only', '@{upstream}..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 });
                    unpushedFiles = unpushedOutput.split('\n')
                        .filter(l => l.trim().length > 0)
                        .map(f => ({ status: 'C ', file: f.trim() })); // 'C ' = committed
                } catch (e) {
                    // No upstream set — try comparing with HEAD~1
                    try {
                        const fallbackOutput = execFileSync('git', ['diff', '--name-only', 'HEAD~1..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 });
                        unpushedFiles = fallbackOutput.split('\n')
                            .filter(l => l.trim().length > 0)
                            .map(f => ({ status: 'C ', file: f.trim() }));
                    } catch (e2) { /* no history yet */ }
                }
            }

            // Merge both sources, deduplicate by filename
            const allFiles = [...changedFiles];
            const existingFiles = new Set(changedFiles.map(c => normalizePath(c.file)));
            for (const uf of unpushedFiles) {
                if (!existingFiles.has(normalizePath(uf.file))) {
                    allFiles.push(uf);
                }
            }

            const protectedList = db.getProtectedFiles(repo.id).map(p => normalizePath(p.file_path));
            
            for (const item of allFiles) {
                const normFile = normalizePath(item.file);
                const isProtected = protectedList.some(p => normFile === p || normFile.startsWith(p + '/'));
                
                if (isProtected) {
                    if (options.isHook) {
                        // Block staged, modified, or committed files (not untracked '??')
                        if (item.status[0] !== '?') violations.push(item.file);
                    } else {
                        violations.push(item.file);
                    }
                }
            }
        } catch (e) { /* ignore git errors */ }
    }

    let diff = '';
    if (options.isHook) {
        // Only scan what is about to be pushed
        try {
            diff = execFileSync('git', ['diff', '@{u}..HEAD'], { cwd, encoding: 'utf-8', timeout: 10000 }) || '';
        } catch (e) {
            // Fallback: scan last commit if no upstream
            try { diff = execFileSync('git', ['diff', 'HEAD~1..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 }) || ''; } catch(e2) {}
        }
    } else {
        diff = gh.getLocalDiff(cwd) || '';
    }

    const results = scanFile(options.isHook ? 'outgoing.diff' : 'local.diff', diff);

    return {
        success: true,
        alerts: results.alerts,
        violations,
        repo
    };
}

// ─── sentinel prepush (Advisory Pre-Push Analysis) ───
program
    .command('prepush')
    .description('Analyze outbound commits before pushing. Advisory only — does NOT block.')
    .action(() => {
        console.log('\n🛡️  Sentinel Pre-Push Security Analysis');
        console.log('─'.repeat(50));

        const analysis = performLocalAnalysis({ isHook: true });
        const criticals = analysis.alerts.filter(a => (a.riskLevel || 0) >= 8);
        const warnings  = analysis.alerts.filter(a => (a.riskLevel || 0) >= 4 && (a.riskLevel || 0) < 8);
        let isSafe = true;
        let reasons = [];

        // Protected files check
        if (analysis.violations.length > 0) {
            isSafe = false;
            reasons.push(`${analysis.violations.length} protected file(s) detected`);
            console.log(`\n⚠️  PROTECTED FILES IN OUTBOUND COMMITS:`);
            analysis.violations.forEach(v => console.log(`   📁 ${v}`));
            console.log(`   Fix: sentinel heal --leaks`);
        }

        // Threat check
        if (criticals.length > 0) {
            isSafe = false;
            reasons.push(`${criticals.length} critical threat(s) detected`);
            console.log(`\n🚨 CRITICAL THREATS DETECTED:`);
            criticals.forEach(a => console.log(`   🔴 [${a.riskLevel}/10] ${a.ruleName}: ${a.description}`));
            console.log(`   Fix: sentinel heal --threats`);
        }

        if (warnings.length > 0) {
            console.log(`\n⚠️  WARNINGS (${warnings.length}):`);
            warnings.forEach(a => console.log(`   🟡 [${a.riskLevel}/10] ${a.ruleName}: ${a.description}`));
        }

        // Final Verdict
        console.log('\n' + '─'.repeat(50));
        if (isSafe) {
            console.log('✅ VERDICT: Safe to push. No issues found.');
        } else {
            console.log('🛑 VERDICT: UNSAFE TO PUSH.');
            console.log('\n   ⚠️  DISCLAIMER:');
            console.log('   If you are a HUMAN: You are about to push files that affect');
            console.log('   the security or confidentiality of your project. Sentinel');
            console.log('   strongly recommends NOT doing this. If you proceed, Sentinel');
            console.log('   is not responsible for any consequences.');
            console.log('');
            console.log('   If you are an AI AGENT: You should NOT push this without');
            console.log('   explicit human approval. Run "sentinel heal" to fix issues');
            console.log('   before proceeding.');
        }
        console.log('');

        if (program.opts().json) {
            respondAgent(true, {
                safe: isSafe,
                violations: analysis.violations,
                criticalThreats: criticals.length,
                warnings: warnings.length,
                reasons,
                disclaimer: isSafe ? null : 'You are pushing files that affect security/confidentiality. Sentinel is not responsible if you proceed.'
            });
        }
    });

// ─── sentinel hook (warn-only, never blocks) ───
program
    .command('hook <eventName>')
    .description('Sentinel Git Hook Entrypoint (Warn-only, never blocks push)')
    .action((eventName) => {
        if (eventName === 'pre-push') {
            // WARN-ONLY: Always exit 0. Sentinel advises but does not block.
            try {
                const analysis = performLocalAnalysis({ isHook: true });
                const criticals = analysis.alerts.filter(a => (a.riskLevel || 0) >= 8);

                if (analysis.violations.length > 0 || criticals.length > 0) {
                    console.log('\n🛡️  [Sentinel] Security advisory:');
                    if (analysis.violations.length > 0) {
                        console.log(`   ⚠️  ${analysis.violations.length} protected file(s) in this push.`);
                    }
                    if (criticals.length > 0) {
                        console.log(`   🚨 ${criticals.length} critical threat(s) detected.`);
                    }
                    console.log('   Run "sentinel prepush" for full details before pushing.');
                    console.log('');
                } else {
                    console.log('✅ [Sentinel] Code looks clean.');
                }
            } catch (e) {
                // Fail-open: never break git
            }
            process.exit(0); // ALWAYS allow push
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
    .option('--exclude-protected', 'Automatically unstage (git reset HEAD) any protected files')
    .option('--force', 'Bypass protected files block')
    .action(async (options) => {
        const { execFileSync } = require('child_process');
        console.log('\n🔍 Sentinel: Analyzing local changes...\n');

        const analysis = performLocalAnalysis();
        const cwd = process.cwd();

        if (analysis.violations.length > 0) {
            console.log(`\n⚠️  PROTECTED FILES DETECTED:`);
            analysis.violations.forEach(v => console.log(`   - ${v}`));
            
            if (options.excludeProtected) {
                console.log('\n✅ --exclude-protected flag passed. Unstaging protected files...');
                analysis.violations.forEach(v => {
                    try {
                        execFileSync('git', ['reset', 'HEAD', v], { cwd, timeout: 5000 });
                        console.log(`   Unstaged: ${v}`);
                    } catch (e) {
                        console.log(`   Failed to unstage: ${v}`);
                    }
                });
            } else if (!options.force) {
                console.log('\n🚫 BLOCKED: You are attempting to commit protected files.');
                console.log('   Use: sentinel heal --leaks (to unstage them automatically)');
                process.exit(1);
            }
        }

        const criticals = analysis.alerts.filter(a => (a.riskLevel || 0) >= 8);
        const warnings  = analysis.alerts.filter(a => (a.riskLevel || 0) >= 4 && (a.riskLevel || 0) < 8);

        if (analysis.alerts.length === 0) {
            console.log('✅ No threats detected. Safe to commit.\n');
        } else {
            console.log(`\n🚨 FOUND ${analysis.alerts.length} POTENTIAL THREATS:\n`);
            criticals.forEach(a => console.log(`   [CRITICAL] ${a.ruleName}: ${a.description}`));
            warnings.forEach(a => console.log(`   [WARN] ${a.ruleName}: ${a.description}`));

            if (criticals.length > 0) {
                console.log('\n❌ Commit is NOT recommended. Use sentinel heal --threats to quarantine.');
                process.exit(1);
            } else {
                console.log('\n✓ No critical threats. Proceed with caution.\n');
            }
        }
    });

// ─── sentinel heal [--leaks/--threats] ───
program
    .command('heal')
    .description('Sentinel Guardian Mode: Automatically fix leaks and contain threats')
    .option('--leaks', 'Unstage all files belonging to protected folders')
    .option('--threats', 'Unstage detected threats and move them to quarantine')
    .action((options) => {
        const { execFileSync } = require('child_process');
        const analysis = performLocalAnalysis();
        const cwd = process.cwd();

        if (options.leaks) {
            if (analysis.violations.length === 0) {
                console.log('✅ No protected files detected in the current commit.');
                return;
            }
            console.log('\n🛡️  Sentinel Healing: Unstaging protected files...');
            analysis.violations.forEach(v => {
                try {
                    execFileSync('git', ['reset', 'HEAD', v], { cwd, timeout: 5000 });
                    console.log(`   Restored: ${v}`);
                } catch (e) {
                    console.error(`   Failed to restore ${v}: ${e.message}`);
                }
            });
            console.log('✅ Leaks contained.');
        }

        if (options.threats) {
            const highRisks = analysis.alerts.filter(a => (a.riskLevel || 0) >= 7);
            if (highRisks.length === 0) {
                console.log('✅ No high-risk threats detected locally.');
                return;
            }

            console.log('\n🛡️  Sentinel Healing: Containing threats...');
            const quarantineDir = path.join(cwd, '.sentinel', 'quarantine');
            if (!fs.existsSync(quarantineDir)) fs.mkdirSync(quarantineDir, { recursive: true });

            // Since multiple alerts can point to the same file, collect unique filenames
            const uniqueFiles = [...new Set(analysis.alerts.map(a => a.filename))];

            uniqueFiles.forEach(targetFile => {
                const fullTargetPath = path.resolve(cwd, targetFile);
                if (fs.existsSync(fullTargetPath)) {
                    try {
                        // Unstage from git first
                        execFileSync('git', ['reset', 'HEAD', targetFile], { cwd, timeout: 5000 });
                        
                        // Copy to quarantine
                        const dest = path.join(quarantineDir, `${Date.now()}_${targetFile}`);
                        fs.copyFileSync(fullTargetPath, dest);
                        
                        console.log(`   Quarantined: ${targetFile} -> ${path.relative(cwd, dest)}`);
                        console.log(`   (Successfully unstaged from Git)`);
                    } catch (e) {
                        console.error(`   Partial success. Failed to unstage ${targetFile}: ${e.message}`);
                    }
                }
            });
            console.log('\n✅ Threats contained in quarantine. Review them before proceeding.');
        }

        if (!options.leaks && !options.threats) {
            console.log('   Please specify --leaks or --threats. Use --help for details.');
        }
    });

// ─── sentinel protected [add/list/remove] ───
program
    .command('protected')
    .description('Manage protected files and folders for the current repository')
    .argument('[action]', 'Action to perform (add, list, remove)', 'list')
    .argument('[target]', 'Path to add or ID to remove')
    .action((action, target) => {
        const db = require('../backend/lib/db');
        const cwd = process.cwd();
        const repos = db.getRepositories();
        const repo = repos.find(r => r.local_path && normalizeAbsPath(r.local_path) === normalizeAbsPath(cwd));

        if (!repo) {
            if (program.opts().json) respondAgent(false, null, 'No linked repository found for the current directory.');
            console.error('❌ No linked repository found for the current directory. Link it first: sentinel link . <repo>');
            process.exit(1);
        }

        if (action === 'add') {
            if (!target) {
                console.error('❌ Usage: sentinel protected add <path>');
                process.exit(1);
            }
            const fullPath = path.relative(repo.local_path, path.resolve(target)).replace(/\\/g, '/');
            const id = db.addProtectedFile(repo.id, fullPath);
            if (program.opts().json) respondAgent(true, { id, path: fullPath });
            console.log(`✅ Path protected: ${fullPath} (ID: ${id})`);
        } else if (action === 'remove') {
            if (!target) {
                console.error('❌ Usage: sentinel protected remove <id>');
                process.exit(1);
            }
            const success = db.removeProtectedFile(parseInt(target));
            if (program.opts().json) respondAgent(success, { id: target });
            if (success) console.log(`✅ Removed protection for ID: ${target}`);
            else console.error(`❌ Could not find a protected file with ID: ${target}`);
        } else {
            // Default: List
            const files = db.getProtectedFiles(repo.id);
            if (program.opts().json) respondAgent(true, files);
            
            console.log(`\n🛡️  Protected Files for: ${repo.github_full_name}\n`);
            if (files.length === 0) {
                console.log('   (No files protected yet)');
            } else {
                files.forEach(f => console.log(`   [ID: ${f.id}] ${f.file_path}`));
            }
            console.log('');
        }
    });

// ─── sentinel hook-install ───
program
    .command('hook-install')
    .description('Install the Sentinel Security Skill (Pre-push Git Hook)')
    .action(() => {
        const cwd = process.cwd();
        const gitDir = path.join(cwd, '.git');
        
        if (!fs.existsSync(gitDir)) {
            if (program.opts().json) respondAgent(false, null, 'Not a git repository.');
            console.error('❌ This directory is not a git repository. Execute inside a repo.');
            process.exit(1);
        }

        const hooksDir = path.join(gitDir, 'hooks');
        if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });

        const hookPath = path.join(hooksDir, 'pre-push');
        const hookScript = `node "${path.resolve(__dirname, 'index.js')}" hook pre-push`;
        const hookSignature = '# --- Sentinel Security Hook ---';
        
        const hookContent = `\n${hookSignature}
# Advisory security scan before push (warn-only, never blocks).
${hookScript}
# --- End Sentinel Hook ---\n`;

        try {
            let existingContent = '';
            if (fs.existsSync(hookPath)) {
                existingContent = fs.readFileSync(hookPath, 'utf-8');
            }

            if (existingContent.includes(hookSignature)) {
                if (program.opts().json) respondAgent(true, { installed: true, alreadyExisted: true });
                console.log('✅ Sentinel Security Skill is already installed and up to date.');
                return;
            }

            // If it doesn't have a shebang, add one
            if (existingContent.trim() === '') {
                fs.writeFileSync(hookPath, `#!/bin/sh${hookContent}`, { mode: 0o755 });
            } else {
                fs.appendFileSync(hookPath, hookContent);
            }

            if (program.opts().json) respondAgent(true, { installed: true, hook: 'pre-push' });
            console.log('\n✅ Sentinel Security Skill installed successfully!');
            console.log('   Git hook: .git/hooks/pre-push');
            console.log('\n🛡️  Your outbound commits are now protected.');
        } catch (e) {
            if (program.opts().json) respondAgent(false, null, e.message);
            console.error('❌ Failed to install git hook:', e.message);
            process.exit(1);
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
