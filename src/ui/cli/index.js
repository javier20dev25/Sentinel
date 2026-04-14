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

const appExePath = isPackaged ? process.execPath : path.resolve(__dirname, '..', '..', '..', 'Sentinel.exe');
const isPackagedFinal = isPackaged || fs.existsSync(appExePath);

// Global State
let isJSON = false;

/**
 * Standardized logger for Sentinel.
 * Sends help/info to stderr if in JSON mode, keeping stdout clean for data.
 */
function log(msg, type = 'info') {
    if (isJSON) {
        process.stderr.write(`[Sentinel] ${msg}\n`);
    } else {
        const icons = { info: 'ℹ️', error: '❌', success: '✅', system: '🛡️', warning: '⚠️' };
        console.log(`${icons[type] || ''} ${msg}`);
    }
}

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

    log(`Scanning for threats in ${githubName}...`, 'system');
    let totalAlerts = 0;
    
    // Attempt 1: Fetch and scan PRs via API
    const prs = gh.listPRs(githubName);
    
    if (prs.length > 0) {
        log(`Found ${prs.length} open PR(s) to analyze via API.`, 'info');
        prs.forEach(pr => {
            log(`Checking PR #${pr.number}: ${pr.title}`, 'info');
            const diff = gh.getPRDiff(githubName, pr.number);
            if (diff) {
                const results = scanFile(`PR #${pr.number}.diff`, diff);
                if (results.alerts.length > 0) {
                    processResults(results, `PR #${pr.number}`, pr.number);
                }
            }
        });
    } else if (isCI) {
        // Attempt 2: CI Fallback - Scan all local JS files in the workspace
        log("[Sentinel CI] No PRs detected via API. Performing deep local scan of workspace...", 'warning');
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
        const category = results.alerts.some(a => a.ruleName.includes('Secret')) ? 'SECRETS' : 'MALWARE';
        db.addScanLog(repoId, 'THREAT_DETECTED', 10, `Threats in ${sourceName}`, results.alerts, 'STATIC', category);
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
        log("No threats found.", 'success');
        if (isJSON) console.log(JSON.stringify({ status: 'SAFE', alerts: 0, githubName }));
        process.exit(0);
    } else {
        log(`Found ${totalAlerts} potential threats!`, 'error');
        if (isJSON) console.log(JSON.stringify({ status: 'INFECTED', alerts: totalAlerts, githubName }));
        // In CI, if we find threats, we should fail the job to block the merge effectively
        if (isCI) {
            log("Blocking build due to security threats.", 'error');
            process.exit(1);
        }
        process.exit(1);
    }
}

/**
 * REPO ORCHESTRATION HELPERS
 */
async function performRepoAudit(githubName) {
    const orchestrator = require('../backend/lib/orchestrator');
    
    if (!isJSON) {
        console.log(`\n🛡️ Sentinel: Global Security Audit for ${githubName}`);
        console.log(`────────────────────────────────────────────────────────────`);
    }

    const audit = await orchestrator.auditRepo(githubName);
    if (audit.error) {
        log(`Error: ${audit.error}`, 'error');
        if (isJSON) console.log(JSON.stringify({ error: audit.error }));
        process.exit(2);
    }

    if (isJSON) {
        console.log(JSON.stringify(audit));
        process.exit(audit.score >= 80 ? 0 : 1);
    }

    console.log(`Security Score: ${audit.score}/100 [Grade: ${audit.grade}]`);
    console.log(`────────────────────────────────────────────────────────────`);
    
    audit.checks.forEach(c => {
        const icon = c.status ? '✅' : '❌';
        console.log(`${icon} ${c.name.padEnd(35)} [${c.status ? 'OK' : 'MISSING'}]`);
    });

    console.log(`────────────────────────────────────────────────────────────`);
    if (audit.score < 80) {
        console.log(`⚠️ Recommendation: Run 'sentinel repo-harden --target ${githubName} --preview'`);
    } else {
        console.log(`✅ Status: Repository is well protected.`);
    }
    console.log();
}

async function performRepoHarden(githubName, options) {
    const orchestrator = require('../backend/lib/orchestrator');
    const readline = require('readline');

    if (options.preview) {
        const plan = await orchestrator.planHarden(githubName);
        console.log(`\n🛡️ Sentinel Hardening Plan for ${githubName}`);
        console.log(`────────────────────────────────────────────────────────────`);
        if (plan.plan.length === 0) {
            console.log("✅ Everything is already up to Sentinel Standards.");
            return;
        }

        console.table(plan.plan.map(p => ({
            Action: p.action,
            Feature: p.target,
            Benefit: p.impact
        })));

        console.log(`────────────────────────────────────────────────────────────`);
        console.log(`Total Score Improvement: +${plan.audit.checks.filter(c => !c.status).reduce((a, b) => a + b.points, 0)} points`);
        console.log(`\nTo apply, run: sentinel repo-harden --target ${githubName} --apply`);
        return;
    }

    if (options.apply) {
        // SAFEGUARD: Consent Flow
        console.log(`\n⚠️  SENTINEL SECURITY ORCHESTRATOR ⚠️`);
        console.log(`──────────────────────────────────`);
        console.log(`Target: ${githubName}`);
        console.log(`Action: Apply Sentinel Security Standard v1.0`);
        console.log(`Risk: Critical infrastructure change. This modifies repository settings.`);
        console.log(`──────────────────────────────────`);
        
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        
        const answer = await new Promise(resolve => {
            rl.question(`\nDo you accept the security policy and want to proceed? (Type 'YES' to confirm): `, resolve);
        });
        rl.close();

        if (answer !== 'YES') {
            console.log("❌ Operation aborted by user.");
            return;
        }

        console.log(`🚀 Hardening ${githubName}...`);
        const result = await orchestrator.executeHarden(githubName);
        
        if (result.success) {
            console.log(`\n✅ SUCCESS: ${githubName} is now protected by Sentinel!`);
            result.results.forEach(r => {
                console.log(`   - ${r.step}: OK`);
            });
        } else {
            console.error(`\n❌ FAILED: Some hardening steps could not be completed.`);
        }
    } else {
        console.log("Usage: sentinel repo-harden --target <repo> [--preview|--apply]");
    }
}

/**
 * AI AGENT BRIEFING
 * Optimized for Token usage (<350 tokens) and actionable intelligence.
 */
async function performBriefing(githubName, options) {
    const orchestrator = require('../backend/lib/orchestrator');
    const db = require('../backend/lib/db');
    
    log(`Generating security briefing for ${githubName}...`, 'system');
    
    const audit = await orchestrator.auditRepo(githubName);
    const plan = await orchestrator.planHarden(githubName);
    const repo = db.getRepositoryByFullName(githubName);
    const logs = repo ? db.getLogsByRepoFilter(repo.id).slice(0, 3) : [];

    const briefing = {
        repo: githubName,
        score: audit.score,
        grade: audit.grade,
        top_threats: logs.map(l => ({ level: l.risk_level, msg: l.description })),
        actions: plan.plan.slice(0, 3).map(p => ({ action: p.action, target: p.target }))
    };

    if (options.format === 'json' || isJSON) {
        console.log(JSON.stringify(briefing));
        process.exit(0);
    }

    // Markdown Briefing (Token Optimized)
    let md = `### 🛡️ Sentinel Briefing: ${githubName}\n`;
    md += `**Security Posture:** ${audit.score}/100 [Grade ${audit.grade}]\n\n`;
    
    if (logs.length > 0) {
        md += `**Active Threats:**\n` + logs.map(l => `- [Lvl ${l.risk_level}] ${l.description}`).join('\n') + `\n\n`;
    } else {
        md += `**Active Threats:** None detected.\n\n`;
    }

    if (plan.plan.length > 0) {
        md += `**Recommended Actions:**\n` + plan.plan.slice(0, 3).map(p => `- ${p.action} ${p.target}`).join('\n') + `\n\n`;
    }
    
    md += `*Protocol: exit 0 (healthy), 1 (threats), 2 (error). Status: ${audit.score >= 80 ? 'OK' : 'DEBT'}*`;
    
    console.log(md);
    process.exit(audit.score >= 80 ? 0 : 1);
}

// ─── CLI COMMAND DEFINITIONS ───

program
    .version('1.0.0')
    .description('Sentinel Security CLI')
    .option('--json', 'Output machine-readable JSON to stdout')
    .hook('preAction', (thisCommand) => {
        if (thisCommand.opts().json || program.opts().json) {
            isJSON = true;
        }
    });

program
    .command('link <path> <github_full_name>')
    .description('Link a local project to Sentinel')
    .action(async (localPath, githubName) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const fullPath = path.resolve(localPath);
        
        log(`Linking repository at ${fullPath}...`, 'system');
        
        const info = gh.getRepoInfoLocal(fullPath);
        if (!info) {
            log("Could not identify GitHub repository. Make sure 'gh' is authenticated and you are inside a git repo.", 'error');
            if (isJSON) console.log(JSON.stringify({ error: 'repo_not_identified' }));
            process.exit(2);
        }

        const repoId = db.addRepository(fullPath, info.fullName);
        log(`Success! Linked to ${info.fullName}`, 'success');
        
        if (isJSON) {
            console.log(JSON.stringify({ success: true, id: repoId, fullName: info.fullName }));
        }
        
        await performManualScan(repoId, info.fullName);
    });

program
    .command('list')
    .description('List all linked repositories')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        
        if (isJSON) {
            console.log(JSON.stringify(repos));
        } else {
            console.table(repos.map(r => ({
                ID: r.id,
                Name: r.github_full_name,
                Status: r.status,
                LastScan: r.last_scan_at
            })));
        }
        process.exit(0);
    });

program
    .command('scan')
    .description('Scan all linked repositories now')
    .action(async () => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        let repos = db.getRepositories();
        
        // CI RESILIENCE: If running in GitHub Actions and no repos are linked, auto-link current dir
        if (repos.length === 0 && process.env.GITHUB_ACTIONS === 'true') {
            log("[Sentinel CI] No linked repositories found. Auto-linking current workspace...", 'warning');
            const info = gh.getRepoInfoLocal(process.cwd());
            if (info) {
                const repoId = db.addRepository(process.cwd(), info.fullName);
                repos = [db.getRepositoryById(repoId)];
            } else {
                log("[Sentinel CI] Could not identify GitHub repository from current workspace.", 'error');
                if (isJSON) console.log(JSON.stringify({ error: 'ci_link_failed' }));
                process.exit(2);
            }
        }

        for (const repo of repos) {
            await performManualScan(repo.id, repo.github_full_name);
        }
        process.exit(0);
    });

program
    .command('repo-audit')
    .description('Full security audit (Score) for a repository')
    .requiredOption('--target <repo>', 'Full owner/repo name')
    .action(async (options) => {
        await performRepoAudit(options.target);
    });

program
    .command('repo-harden')
    .description('Apply Sentinel Security Standards to a repository')
    .requiredOption('--target <repo>', 'Full owner/repo name')
    .option('--preview', 'Preview changes before applying')
    .option('--apply', 'Apply changes (requires confirmation)')
    .action(async (options) => {
        await performRepoHarden(options.target, options);
    });

program
    .command('briefing')
    .description('Get a token-optimized security briefing for an AI agent context')
    .requiredOption('--target <repo>', 'Full owner/repo name')
    .option('--format <format>', 'Output format (markdown|json)', 'markdown')
    .action(async (options) => {
        await performBriefing(options.target, options);
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
            log(`Error: ${status.error}`, 'error');
            if (isJSON) console.log(JSON.stringify({ error: status.error }));
            process.exit(2);
        } else {
            if (isJSON) {
                console.log(JSON.stringify(status));
            } else {
                console.log(`Run status: ${status.status}`);
                if (status.conclusion) console.log(`Conclusion: ${status.conclusion}`);
                console.log(`URL: ${status.url}`);
            }
            process.exit(0);
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
