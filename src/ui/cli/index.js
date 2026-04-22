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
 */
function normalizePath(p) {
    if (!p) return '';
    return path.normalize(p).toLowerCase().replace(/\\/g, '/');
}

/**
 * Handles terminal coloring suppression based on --no-color or environment.
 */
function useColors() {
    return !program.opts().noColor && process.stdout.isTTY;
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

const appExePath = isPackaged ? process.execPath : path.resolve(__dirname, '..', '..', '..', 'Sentinel.exe');
const isPackagedFinal = isPackaged || fs.existsSync(appExePath);

/**
 * Generates a professional Markdown report for GitHub visibility.
 */
function generateMarkdownReport(githubName, prNumber, alerts) {
    let report = `## 🛡️ Sentinel: Security Threat Detected in PR #${prNumber}\n\n`;
    report += `**Repository:** ${githubName}\n`;
    report += `**Status:** 🚨 THREAT FOUND\n\n`;
    report += `Sentinel has identified potential security risks in this proposal.\n\n`;
    
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
    
    const prs = gh.listPRs(githubName);
    
    if (prs.length > 0) {
        prs.forEach(pr => {
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
            }
        });
    }

    function processResults(results, sourceName, prNumber = null) {
        totalAlerts += results.alerts.length;
        db.addScanLog(repoId, 'THREAT_DETECTED', 10, `Threats in ${sourceName}`, results.alerts);
        db.updateRepoStatus(repoId, 'INFECTED');
        
        safeNotify({
            title: '🚨 Sentinel: Threat Detected!',
            message: `${sourceName} looks dangerous.`,
            sound: true
        });

        if (prNumber) {
            const mdReport = generateMarkdownReport(githubName, prNumber, results.alerts);
            gh.postPRComment(githubName, prNumber, mdReport);
        }

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
        if (isCI) {
            console.error("❌ Blocking build due to security threats.");
            process.exit(1);
        }
    }
}

/**
 * Local Analysis Engine (Git Diff or Full Scan)
 */
function performLocalAnalysis(options = {}) {
    const gh = require('../backend/lib/gh_bridge');
    const db = require('../backend/lib/db');
    const scanner = require('../backend/scanner/index'); // Reuse backend scanner
    const { execFileSync } = require('child_process');
    const cwd = process.cwd();

    const repos = db.getRepositories();
    const repo = repos.find(r => r.local_path && normalizeAbsPath(r.local_path) === normalizeAbsPath(cwd));
    
    let violations = [];
    let scannedFiles = [];

    if (options.all) {
        // Full Directory Scan
        const fullResults = scanner.scanDirectory(cwd);
        return {
            success: true,
            alerts: [], // Direct access to details below
            details: fullResults.details,
            threats: fullResults.threats,
            filesScanned: fullResults.filesScanned,
            repo
        };
    }

    if (repo) {
        try {
            const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf-8', timeout: 5000 });
            const changedFiles = statusOutput.split('\n')
                .filter(l => l.trim().length > 0)
                .map(l => ({ status: l.substring(0, 2), file: l.substring(3).trim() }));
            
            let unpushedFiles = [];
            if (options.isHook) {
                try {
                    const unpushedOutput = execFileSync('git', ['diff', '--name-only', '@{upstream}..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 });
                    unpushedFiles = unpushedOutput.split('\n')
                        .filter(l => l.trim().length > 0)
                        .map(f => ({ status: 'C ', file: f.trim() }));
                } catch (e) {
                    try {
                        const fallbackOutput = execFileSync('git', ['diff', '--name-only', 'HEAD~1..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 });
                        unpushedFiles = fallbackOutput.split('\n')
                            .filter(l => l.trim().length > 0)
                            .map(f => ({ status: 'C ', file: f.trim() }));
                    } catch (e2) {}
                }
            }

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
                    if (item.status[0] !== '?') violations.push(item.file);
                }
            }
        } catch (e) {}
    }

    let diff = '';
    if (options.isHook) {
        try {
            diff = execFileSync('git', ['diff', '@{u}..HEAD'], { cwd, encoding: 'utf-8', timeout: 10000 }) || '';
        } catch (e) {
            try { diff = execFileSync('git', ['diff', 'HEAD~1..HEAD'], { cwd, encoding: 'utf-8', timeout: 5000 }) || ''; } catch(e2) {}
        }
    } else {
        diff = gh.getLocalDiff(cwd) || '';
    }

    const results = scanner.scanFile(options.isHook ? 'outgoing.diff' : 'local.diff', diff);

    return {
        success: true,
        alerts: results.alerts,
        violations,
        repo
    };
}

// ─── CLI COMMAND DEFINITIONS ───

const renderer = require('./renderer');
const pc = require('picocolors');

program
    .name('sentinel')
    .version('3.6.1')
    .description('Sentinel Security Guardian — Enterprise SAST & Decision Engine')
    .option('--json', 'Machine-readable output (JSON)')
    .option('--no-color', 'Disable terminal colors (useful for log files/CI)')
    .hook('preAction', () => {
        // Ensure rules are loaded before any action that might use them
        const scanner = require('../backend/scanner/index');
        try { scanner.loadRules(); } catch (e) {}
    });

// ─── sentinel scan (v3.6 Unified Scanner) ───
program
    .command('scan')
    .description('Scan current repository or specific path for threats.')
    .argument('[path]', 'Directory or file to scan', '.')
    .option('--ci', 'CI Mode: Minimal silent output with deterministic exit codes')
    .option('--debug', 'Verbose mode: Print raw breakdown metrics')
    .option('--fast', 'Fast Mode: Skip deep analysis and sandbox (Speed priority)')
    .option('--mode <type>', 'Analysis mode: local or sandbox', 'local')
    .option('--source <type>', 'Event source: cli or github-action', 'cli')
    .action((targetPath, options) => {
        const gh = require('../backend/lib/gh_bridge');
        const scanner = require('../backend/scanner/index');
        const db = require('../backend/lib/db');
        const Orchestrator = require('../backend/scanner/gate_orchestrator');
        const target = normalizeAbsPath(targetPath);
        
        const computeConfidence = (execution) => execution === 'isolated' ? 92 : 65;
        
        let fileList = [];
        const stats = fs.statSync(target, { throwIfNoEntry: false });
        if (stats && stats.isDirectory()) {
            fileList = fs.readdirSync(target);
        } else {
            fileList = [target];
        }

        // 1. Auto-Escalation Logic
        const gateInfo = Orchestrator.resolveGateLevel(fileList);
        const activeLevel = options.gateLevel || (options.fast ? 0 : gateInfo.level);
        options.gateLevel = activeLevel;

        if (!options.ci && !program.opts().json) {
            console.log(pc.bold(pc.cyan(`\n[Sentinel] Mode: ${Orchestrator.getLevelLabel(activeLevel)}`)));
            if (activeLevel > 0) console.log(pc.dim(`Reason: ${gateInfo.reason}`));
        }

        let results = null;
        if (stats && stats.isFile()) {
            const content = fs.readFileSync(target, 'utf8');
            const scan = scanner.scanFile(path.basename(target), content, null, options);
            scan.alerts.forEach(a => { a._file = path.basename(target); a._fullPath = target; });
            const executionMode = options.fast ? 'none' : (options.mode === 'sandbox' ? 'isolated' : 'none');
            results = {
                version: "3.6.1",
                rulepack_version: "2026.04",
                context: {
                    analysis_mode: options.mode,
                    execution: executionMode,
                    source: options.source,
                    gate_level: activeLevel
                },
                summary: {
                    confidence_score: computeConfidence(executionMode),
                    confidence_source: "engine"
                },
                threats: scan.alerts.length,
                filesScanned: 1,
                rawAlerts: scan.alerts
            };
        } else {
            // Directory Scan
            results = scanner.scanDirectory(target, options);
            const executionMode = options.fast ? 'none' : (options.mode === 'sandbox' ? 'isolated' : 'none');
            results.version = "3.6.1";
            results.rulepack_version = "2026.04";
            results.context = {
                analysis_mode: options.mode,
                execution: executionMode,
                source: options.source,
                gate_level: activeLevel
            };
            results.summary = {
                confidence_score: computeConfidence(executionMode),
                confidence_source: "engine"
            };
        }

        // 2. Classify Results for Semantic Exit Codes
        const securityFindings = (results.rawAlerts || []).filter(a => a.classification === 'SECURITY');
        const policyViolations = (results.rawAlerts || []).filter(a => a.classification === 'POLICY');

        if (program.opts().json) {
            respondAgent(true, results);
        } else if (options.ci) {
            // Semantic Exit Code Contract [0-3]
            if (results.threats === 0) process.exit(0);
            if (securityFindings.length > 0) process.exit(1);
            if (policyViolations.length > 0) process.exit(2);
            process.exit(0);
        } else {
            renderer.renderHierarchicalReport(results.rawAlerts || [], results.filesScanned, { gateLevel: activeLevel, noColor: program.opts().noColor });
            
            // Terminal Final Verdict / Exit Code
            if (results.threats > 0) {
                if (securityFindings.length > 0) process.exit(1);
                process.exit(2);
            }
        }
    });

// ─── sentinel explain (v3.6) ───
program
    .command('explain')
    .description('Explain the logic and heuristics behind a flagged file.')
    .argument('<file>', 'File path to explain')
    .action((file) => {
        const scanner = require('../backend/scanner/index');
        const stat = fs.statSync(file, { throwIfNoEntry: false });
        if (!stat || !stat.isFile()) {
            console.error(pc.red(`❌ Target is not a file: ${file}`));
            process.exit(1);
        }
        
        const content = fs.readFileSync(file, 'utf8');
        const scan = scanner.scanFile(path.basename(file), content);
        
        if (program.opts().json) {
            respondAgent(true, scan.alerts);
        } else {
            if (scan.alerts.length === 0) {
                 console.log(pc.green(`✅ File is SAFE. No heuristics triggered.`));
                 return;
            }
            // Explain top threat
            const topThreat = scan.alerts.sort((a,b) => b.riskLevel - a.riskLevel)[0];
            topThreat._file = file;
            renderer.renderExplain(topThreat);
        }
    });

// ─── sentinel trace (v3.6) ───
program
    .command('trace')
    .description('Print execution flow and transformations detected on the file.')
    .argument('<file>', 'File path to trace')
    .action((file) => {
        const scanner = require('../backend/scanner/index');
        const stat = fs.statSync(file, { throwIfNoEntry: false });
        if (!stat || !stat.isFile()) {
            console.error(pc.red(`❌ Target is not a file: ${file}`));
            process.exit(1);
        }
        
        const content = fs.readFileSync(file, 'utf8');
        const scan = scanner.scanFile(path.basename(file), content);
        
        if (program.opts().json) {
            respondAgent(true, scan.alerts);
        } else {
             if (scan.alerts.length === 0) {
                 console.log(pc.green(`✅ File is SAFE. No traces built.`));
                 return;
            }
            const topThreat = scan.alerts.sort((a,b) => b.riskLevel - a.riskLevel)[0];
            renderer.renderTrace(topThreat);
        }
    });

// ─── sentinel prepush (Advisory Pre-Push Analysis) ───
program
    .command('prepush')
    .description('Analyze outbound commits before pushing. Advisory only — does NOT block.')
    .action(() => {
        const analysis = performLocalAnalysis({ isHook: true });
        
        if (program.opts().json) {
            respondAgent(true, {
                safe: analysis.violations.length === 0,
                violations: analysis.violations,
                alerts: analysis.alerts
            });
            return;
        }

        console.log('\n🛡️  Sentinel Pre-Push Security Analysis');
        console.log('─'.repeat(50));

        if (analysis.violations.length > 0) {
            console.log(`\n⚠️  PROTECTED FILES IN OUTBOUND COMMITS:`);
            analysis.violations.forEach(v => console.log(`   📁 ${v}`));
            console.log(`\n   Fix: sentinel heal --leaks`);
        }

        console.log('\n' + '─'.repeat(50));
        if (analysis.violations.length === 0) {
            console.log('✅ VERDICT: Safe to push. No issues found.');
        } else {
            console.log('🛑 VERDICT: UNSAFE TO PUSH.');
            console.log('\n   ⚠️  DISCLAIMER:');
            console.log('   If you are a HUMAN: You are about to push files that affect');
            console.log('   the security or confidentiality of your project. Sentinel');
            console.log('   strongly recommends NOT doing this.');
            console.log('\n   If you are an AI AGENT: You should NOT push this without');
            console.log('   explicit human approval. Run "sentinel heal" to fix issues.');
        }
        console.log('');
    });

// ─── sentinel hook (the actual Git hook entrypoint) ───
program
    .command('hook <eventName>')
    .description('Sentinel Git Hook Entrypoint (Smart-block mode)')
    .action((eventName) => {
        if (eventName === 'pre-push') {
            const hasBypass = process.env.SENTINEL_BYPASS === '1';
            try {
                const analysis = performLocalAnalysis({ isHook: true });
                if (analysis.violations.length > 0) {
                    if (hasBypass) {
                        console.log('\n⚠️  [Sentinel] Bypass active. Allowing push with protected files...');
                        process.exit(0);
                    }
                    console.log('\n🛑  [Sentinel] SECURITY THREAT BLOCKED');
                    console.log(`   ⚠️  At least ${analysis.violations.length} protected file(s) would be exposed in this push.`);
                    analysis.violations.forEach(v => console.log(`      - ${v}`));
                    console.log('\n   🛠️  To safely fix this: run "sentinel heal --leaks"');
                    console.log('   🔓 To FORCE push (take absolute responsibility): run "SENTINEL_BYPASS=1 git push"');
                    console.log('');
                    process.exit(1); // Block the push
                } else {
                    console.log('✅ [Sentinel] Code looks clean.');
                    process.exit(0);
                }
            } catch (e) {
                process.exit(0); // Failsafe allows push on unknown errors
            }
        }
    });

// ─── sentinel hook-install (Idempotent Hook Installer) ───
program
    .command('hook-install')
    .description('Install the Sentinel pre-push hook into the current repository.')
    .action(() => {
        const cwd = process.cwd();
        const hooksDir = path.join(cwd, '.git', 'hooks');
        const hookPath = path.join(hooksDir, 'pre-push');
        const sentinel = 'sentinel';

        if (!fs.existsSync(path.join(cwd, '.git'))) {
            console.error('❌ Not a git repository. Run this from the root of a git repo.');
            if (program.opts().json) respondAgent(false, null, 'Not a git repository');
            process.exit(1);
        }

        const hookContent = `#!/bin/sh\n# Sentinel Security Guardian — Smart Pre-Push Hook\n${sentinel} hook pre-push\nexit $?\n`;

        if (fs.existsSync(hookPath)) {
            const existing = fs.readFileSync(hookPath, 'utf-8');
            if (existing.includes('sentinel hook pre-push')) {
                // Si existe pero está obsoleto con 'exit 0', forzamos el reemplazo a la versión segura:
                if (existing.includes('EVER block') || existing.includes('exit 0')) {
                     fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
                     console.log('✅ Sentinel hook updated to smart-block mode.');
                     if (program.opts().json) respondAgent(true, { status: 'updated' });
                     return;
                }
                console.log('✅ Sentinel hook already installed. No changes needed.');
                if (program.opts().json) respondAgent(true, { status: 'already_installed' });
                return;
            }
            // Append to existing hook
            fs.appendFileSync(hookPath, `\n# Sentinel Security Guardian — Appended\n${sentinel} hook pre-push\nexit $?\n`);
            console.log('✅ Sentinel hook appended to existing pre-push hook.');
            if (program.opts().json) respondAgent(true, { status: 'appended' });
            return;
        }

        if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });
        fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
        console.log('✅ Sentinel pre-push hook installed successfully.');
        console.log(`   Location: ${hookPath}`);
        if (program.opts().json) respondAgent(true, { status: 'installed', path: hookPath });
    });

// ─── sentinel audit (One-shot Directory Audit / Forensic) ───
program
    .command('audit')
    .argument('[path]', 'Directory to audit', '.')
    .option('--forensic', 'Enable deepest forensic scan (scans hidden files, node_modules)')
    .description('Perform a deep, one-shot security audit of a local directory.')
    .action(async (dirPath, options) => {
        const scanner = require('../backend/scanner/index');
        const Orchestrator = require('../backend/scanner/gate_orchestrator');
        
        const finalPath = path.resolve(dirPath);
        const scanOptions = { 
            gateLevel: options.forensic ? 4 : 1,
            forensic: options.forensic
        };

        if (!program.opts().json) {
            console.log(pc.bold(pc.magenta(`\n🛡️  Sentinel Audit Initiation`)));
            console.log(pc.dim('─'.repeat(40)));
            console.log(`Mode: ${Orchestrator.getLevelLabel(scanOptions.gateLevel)}`);
            console.log(`Target: ${finalPath}\n`);
        }

        const results = scanner.scanDirectory(finalPath, scanOptions);
        
        if (program.opts().json) {
            respondAgent(true, results);
        } else {
            renderer.renderHierarchicalReport(results.rawAlerts || [], results.filesScanned, { gateLevel: scanOptions.gateLevel });
            
            if (results.threats > 0) {
                const securityCount = (results.rawAlerts || []).filter(a => a.classification === 'SECURITY').length;
                process.exit(securityCount > 0 ? 1 : 2);
            } else {
                console.log(pc.green('✅ Audit clean. No threats identified.'));
                process.exit(0);
            }
        }
    });

// ─── sentinel open ───
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
                spawn(appExePath, ['.'], { detached: true, stdio: 'ignore' });
                process.exit(0);
            }
            await postIntent(intentPayload);
            console.log("✅ Sentinel UI navigated successfully.");
        } catch (e) {
            console.error("❌ Communication error: Sentinel UI might not be running.");
        }
    });

// ─── sentinel sandbox ───
const sandbox = program
    .command('sandbox')
    .description('Manage local and remote Sentinel Sandbox Guardians');

sandbox
    .command('status')
    .description('Show sandbox status for all linked repos or a specific run')
    .argument('[repo]', 'Repository full name')
    .argument('[runId]', 'Specific Run ID')
    .action(async (repo, runId) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const ci = require('../backend/lib/ci_sandbox');
        
        if (repo && runId) {
            const status = ci.getSandboxRunStatus(repo, parseInt(runId));
            if (status.error) console.error(`❌ Error: ${status.error}`);
            else {
                console.log(`Run status: ${status.status}`);
                if (status.conclusion) console.log(`Conclusion: ${status.conclusion}`);
                console.log(`URL: ${status.url}`);
            }
            return;
        }

        const repos = db.getRepositories();
        const results = repos.map(r => {
            const installed = r.local_path ? gh.checkSandboxInstalled(r.local_path) : { installed: false };
            const run = gh.getLatestSandboxRun(r.github_full_name);
            return { fullName: r.github_full_name, installed: installed.installed, version: installed.version, latestRun: run };
        });

        if (program.opts().json) respondAgent(true, results);
        console.log('\n🛡️  Sentinel Sandbox Status\n');
        results.forEach(res => {
            const statusIcon = !res.installed ? '⚪ Not configured' : (!res.latestRun ? '🟡 No runs' : (res.latestRun.conclusion === 'success' ? '🟢 Clean' : '🔴 Threat'));
            console.log(`  ${res.fullName} -> ${statusIcon}`);
        });
    });

sandbox
    .command('sync')
    .description('Install or update sandbox workflow')
    .option('--auto', 'Auto-install via git push')
    .option('--branch <name>', 'Create a new branch for the sandbox update (for protected repos)')
    .action(async (options) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const repos = db.getRepositories().filter(r => r.local_path);
        
        if (repos.length === 0) {
            console.error('❌ No local repository linked.');
            if (program.opts().json) respondAgent(false, null, 'No local repository linked');
            return;
        }

        const repo = repos[0];
        if (options.auto || options.branch) {
            const pushResult = gh.pushSandboxConfig(repo.local_path, options.branch);
            if (pushResult.success) {
                db.setSandboxConsent(repo.id, true);
                const msg = options.branch ? `✅ Sandbox pushed to branch: ${options.branch}` : '✅ Sandbox pushed to GitHub automatically!';
                console.log(msg);
                if (program.opts().json) respondAgent(true, { status: 'pushed', path: pushResult.path, branch: options.branch });
            } else {
                console.error(`❌ Failed to push Sandbox Config: ${pushResult.error}`);
                if (program.opts().json) respondAgent(false, null, pushResult.error);
            }
        } else {
            const template = gh.getSandboxTemplateContent();
            fs.writeFileSync('sentinel-sandbox.yml', template);
            console.log('✅ Template saved to sentinel-sandbox.yml locally.');
            console.log('   ⚠️  NOTE: Run with --auto to push this to GitHub Actions automatically.');
            if (program.opts().json) respondAgent(true, { status: 'generated_locally', file: 'sentinel-sandbox.yml', note: 'Manual push required, or use --auto' });
        }
    });

sandbox
    .command('audit-prs')
    .argument('[repo]', 'Optional: specific repo name (owner/repo)')
    .description('Audit open PRs by automatically linking them with Sandbox telemetry.')
    .action(async (repoArg) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const ci = require('../backend/lib/ci_sandbox');
        const fs = require('fs');
        const repos = db.getRepositories();
        
        let targets = repos;
        if (repoArg) targets = repos.filter(r => r.github_full_name === repoArg);
        
        if (targets.length === 0) {
            console.error('❌ No linked repositories found.');
            if (program.opts().json) respondAgent(false, null, 'No linked repositories found.');
            return;
        }

        if (!program.opts().json) console.log('🔍 Fetching open Pull Requests and checking Sandbox telemetry...\n');
        const results = [];

        for (const repo of targets) {
            const prs = gh.listPRs(repo.github_full_name) || [];
            const recentPrs = prs.slice(0, 5);

            for (const pr of recentPrs) {
                const branch = pr.headRefName;
                const runResult = {
                    pr_number: pr.number,
                    pr_title: pr.title,
                    repo: repo.github_full_name,
                    branch: branch,
                    sandbox_run_found: false,
                    sandbox_status: null,
                    telemetry_analysis: null,
                    error: null
                };

                if (branch) {
                    const run = ci.getSandboxRunForBranch(repo.github_full_name, branch);
                    if (run && run.id) {
                        runResult.sandbox_run_found = true;
                        runResult.sandbox_status = run.conclusion || run.status;
                        
                        if (run.status === 'completed') {
                            const artifacts = await ci.downloadSandboxArtifacts(repo.github_full_name, run.id);
                            if (!artifacts.error && artifacts.tempDir) {
                                const analysis = await ci.analyzeTelemetry(artifacts.tempDir);
                                runResult.telemetry_analysis = analysis;
                                ci.cleanupTempDir(artifacts.tempDir);
                            } else {
                                runResult.error = artifacts.error || 'Failed to download artifacts';
                            }
                        }
                    }
                }
                results.push(runResult);
            }
        }

        if (program.opts().json) {
            respondAgent(true, { audited_prs: results.length, data: results });
        } else {
            console.log('🛡️  Sentinel Sandbox PR Audit Report');
            console.log('─'.repeat(50));
            let mdContent = '# Sentinel Sandbox PR Audit Report\n\n';
            
            if (results.length === 0) {
                console.log('📭 No open PRs found to audit.');
                mdContent += '**Result:** No open PRs found to audit.\n';
            } else {
                results.forEach(res => {
                    const header = `📦 PR #${res.pr_number} (${res.repo}): ${res.pr_title}`;
                    console.log(`\n${header}`);
                    console.log(`   Branch: ${res.branch}`);
                    mdContent += `## ${header}\n- **Branch:** ${res.branch}\n`;
                    
                    if (!res.sandbox_run_found) {
                        console.log('   ⚪  Sandbox Run: Not Found (Sandbox might not be installed or triggered yet)');
                        mdContent += '- **Sandbox Run:** Not Found\n';
                    } else if (res.sandbox_status !== 'success' && res.sandbox_status !== 'failure') {
                        console.log(`   ⏳  Sandbox Run: In Progress / Queued [Status: ${res.sandbox_status}]`);
                        mdContent += `- **Sandbox Run:** In Progress / Queued [Status: ${res.sandbox_status}]\n`;
                    } else {
                        const icon = res.telemetry_analysis?.safe ? '🟢' : '🔴';
                        console.log(`   ${icon}  Sandbox Run: Completed (${res.sandbox_status})`);
                        mdContent += `- **Sandbox Run:** Completed (${res.sandbox_status})\n`;
                        
                        if (res.telemetry_analysis) {
                            console.log(`       Safe: ${res.telemetry_analysis.safe}`);
                            console.log(`       Threats Found: ${res.telemetry_analysis.threats.length}`);
                            mdContent += `- **Safe:** ${res.telemetry_analysis.safe}\n- **Threats Found:** ${res.telemetry_analysis.threats.length}\n\n`;
                            
                            res.telemetry_analysis.threats.forEach(t => {
                                console.log(`         - [${t.severity}] ${t.rule}: ${t.file}`);
                                mdContent += `  - **[${t.severity}] ${t.rule}**: \`${t.file}\`\n`;
                            });
                        } else if (res.error) {
                            console.log(`       ⚠️  Error analyzing telemetry: ${res.error}`);
                            mdContent += `- **Error:** \`${res.error}\`\n`;
                        }
                    }
                    console.log(`   [Action] -> To close manually, run: gh pr close ${res.pr_number} --repo ${res.repo} -c "Closed due to security concerns"`);
                    mdContent += `\n**Manual Action:**\n\`\`\`bash\ngh pr close ${res.pr_number} --repo ${res.repo} -c "Closed due to security concerns"\n\`\`\`\n\n`;
                });
            }
            console.log('\n' + '─'.repeat(50));
            
            try {
                fs.writeFileSync('sentinel-report.md', mdContent);
                console.log('✅ A detailed Markdown report has been saved to "sentinel-report.md"');
            } catch (e) {
                console.log('⚠️  Failed to write sentinel-report.md to disk.');
            }
        }
    });


// ─── sentinel prs ───
program
    .command('prs')
    .argument('[repo]', 'Optional: specific repo name (owner/repo)')
    .description('List open Pull Requests for linked repositories.')
    .action((repoArg) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const repos = db.getRepositories();
        
        let targets = repos;
        if (repoArg) targets = repos.filter(r => r.github_full_name === repoArg);
        
        if (targets.length === 0) {
            console.log('📭 No repositories found.');
            if (program.opts().json) respondAgent(true, { prs: [] });
            return;
        }

        let allPrs = [];
        targets.forEach(r => {
            const prs = gh.listPRs(r.github_full_name) || [];
            if (prs.length > 0) {
                prs.forEach(pr => allPrs.push({ repo: r.github_full_name, ...pr }));
            }
        });

        if (program.opts().json) {
            respondAgent(true, { count: allPrs.length, prs: allPrs });
        } else {
            if (allPrs.length === 0) {
                console.log('\n📭 No open PRs found for the selected repositories.\n');
                return;
            }
            console.log(`\n🛡️  Sentinel — Open Pull Requests [${allPrs.length}]\n`);
            allPrs.forEach(pr => {
                console.log(`  [#${pr.number}] ${pr.repo} — ${pr.title}`);
                console.log(`         Author: ${pr.author?.login || 'unknown'} | Updated: ${pr.updatedAt || 'unknown'}\n`);
            });
        }
    });


// ─── sentinel packs ───
program
    .command('packs')
    .argument('<action>', 'load')
    .argument('[file]', 'path')
    .action((action, file) => {
        if (action === 'load' && file) {
            const db = require('../backend/lib/db');
            const packData = JSON.parse(fs.readFileSync(file, 'utf8'));
            const repo = db.getRepositories().find(r => r.local_path && path.resolve(r.local_path) === path.resolve(process.cwd()));
            if (repo) {
                try {
                    db.installPack(repo.id, packData, true);
                    console.log('✅ Pack loaded.');
                    if (program.opts().json) respondAgent(true, { status: 'loaded', repo: repo.github_full_name });
                } catch (e) {
                    console.error(`❌ Error loading pack: ${e.message}`);
                    if (program.opts().json) respondAgent(false, null, e.message);
                }
            } else {
                console.error('❌ Could not determine linked repository for the current directory.');
                if (program.opts().json) respondAgent(false, null, 'No linked repository found for current directory');
            }
        } else {
            console.error('❌ Invalid or missing arguments.');
            if (program.opts().json) respondAgent(false, null, 'Invalid arguments for packs command');
        }
    });



// ─── sentinel heal ───
program
    .command('heal')
    .option('--leaks', 'Unstage protected files from staging area and provide instructions for committed leaks')
    .action((options) => {
        const { execFileSync } = require('child_process');
        const cwd = process.cwd();

        if (options.leaks) {
            const analysis = performLocalAnalysis({ isHook: true });

            if (analysis.violations.length === 0) {
                console.log('✅ No leaks found.');
                if (program.opts().json) respondAgent(true, { healed: 0, committed_leaks: [] });
                return;
            }

            const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf-8' });
            const stagedFiles = new Set(
                statusOutput.split('\n')
                    .filter(l => l.length >= 3 && l[0] !== ' ' && l[0] !== '?')
                    .map(l => normalizePath(l.substring(3).trim()))
            );

            let stagedLeaks = [];
            let committedLeaks = [];
            let totalHealed = 0;

            analysis.violations.forEach(v => {
                if (stagedFiles.has(normalizePath(v))) stagedLeaks.push(v);
                else committedLeaks.push(v);
            });

            // Safely unstage files
            stagedLeaks.forEach(v => {
                try {
                    execFileSync('git', ['restore', '--staged', v], { cwd });
                    console.log(`   ✅ Unstaged: ${v}`);
                    totalHealed++;
                } catch (e) {
                    try {
                        execFileSync('git', ['reset', 'HEAD', v], { cwd });
                        console.log(`   ✅ Unstaged (fallback): ${v}`);
                        totalHealed++;
                    } catch (e2) {
                        console.log(`   ❌ Failed to unstage: ${v}`);
                    }
                }
            });

            if (totalHealed > 0) {
                console.log(`✅ Healing complete. Safely unstaged ${totalHealed} protected file(s).`);
            }

            if (committedLeaks.length > 0) {
                console.log('\n⚠️  MANUAL INTERVENTION REQUIRED FOR COMMITTED LEAKS');
                console.log('   The following protected files are already inside your commits:');
                committedLeaks.forEach(v => console.log(`      - ${v}`));
                console.log('\n   Sentinel avoids rewriting your Git history automatically as it can be destructive.');
                console.log('   To fix this safely, undo your recent commits:');
                console.log('      1. Run `git reset HEAD~1` to undo your last commit without losing changes.');
                console.log('      2. Unstage the protected files using `sentinel heal --leaks`.');
                console.log('      3. Re-commit your safe files.');
                console.log('   If you are absolutely certain you want to push anyway, bypass Sentinel with:');
                console.log('      SENTINEL_BYPASS=1 git push\n');
            }

            if (program.opts().json) {
                respondAgent(true, { 
                    healed: totalHealed, 
                    staged_leaks_removed: stagedLeaks,
                    committed_leaks_remaining: committedLeaks 
                });
            }
        }
    });

// ─── sentinel protected ───
program
    .command('protected')
    .argument('[action]', 'list|add|remove', 'list')
    .argument('[target]', 'path or ID')
    .action((action, target) => {
        const db = require('../backend/lib/db');
        const repo = db.getRepositories().find(r => r.local_path && normalizeAbsPath(r.local_path) === normalizeAbsPath(process.cwd()));
        if (!repo) {
            if (program.opts().json) respondAgent(false, null, 'No linked repository found for current directory');
            else console.error('❌ Could not determine linked repository for the current directory.');
            return;
        }

        if (action === 'add' && target) {
            const rel = path.relative(repo.local_path, path.resolve(target)).replace(/\\/g, '/');
            db.addProtectedFile(repo.id, rel);
            if (program.opts().json) {
                respondAgent(true, { status: 'added', path: rel });
            } else {
                console.log(`✅ ${rel} is now protected.`);
            }
        } else if (action === 'remove' && target) {
            db.removeProtectedFile(target);
            if (program.opts().json) {
                respondAgent(true, { status: 'removed', id: target });
            } else {
                console.log(`✅ Protection ID ${target} removed.`);
            }
        } else {
            const files = db.getProtectedFiles(repo.id);
            if (program.opts().json) {
                respondAgent(true, { protected_files: files });
            } else {
                if (files.length === 0) console.log('📭 No protected files.');
                files.forEach(f => console.log(`[ID: ${f.id}] - ${f.file_path}`));
            }
        }
    });

// ─── sentinel config ───
const configCmd = program.command('config').description('Manage Sentinel security specifications and weights');

configCmd
    .command('view')
    .description('View the current security specification details.')
    .action(() => {
        const specPath = path.join(__dirname, '..', 'backend', 'scanner', 'rules', 'sentinel-spec.json');
        if (!fs.existsSync(specPath)) {
            console.error('❌ Security specification file not found.');
            if (program.opts().json) respondAgent(false, null, 'Spec file not found');
            return;
        }
        try {
            const spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
            if (program.opts().json) {
                respondAgent(true, spec);
            } else {
                console.log('\n🛡️  Sentinel Security Specification\n');
                console.log(JSON.stringify(spec, null, 2));
                console.log('\nLocation:', specPath);
            }
        } catch (e) {
            console.error(`❌ Error reading specification: ${e.message}`);
            if (program.opts().json) respondAgent(false, null, e.message);
        }
    });

configCmd
    .command('set <path> <value>')
    .description('Update a security weight or configuration (e.g. "dependency_risk.versioning.unpinned.weight" "75").')
    .action((keyPath, value) => {
        const specPath = path.join(__dirname, '..', 'backend', 'scanner', 'rules', 'sentinel-spec.json');
        try {
            const spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
            const keys = keyPath.split('.');
            let current = spec;
            
            for (let i = 0; i < keys.length - 1; i++) {
                if (!current[keys[i]]) current[keys[i]] = {};
                current = current[keys[i]];
            }
            
            // Try to parse value as number or boolean if possible
            let parsedValue = value;
            if (value.toLowerCase() === 'true') parsedValue = true;
            else if (value.toLowerCase() === 'false') parsedValue = false;
            else if (!isNaN(Number(value))) parsedValue = Number(value);
            
            current[keys[keys.length - 1]] = parsedValue;
            
            fs.writeFileSync(specPath, JSON.stringify(spec, null, 2));
            console.log(`✅ Updated ${keyPath} to: ${parsedValue}`);
            if (program.opts().json) respondAgent(true, { path: keyPath, newValue: parsedValue });
        } catch (e) {
            console.error(`❌ Error updating specification: ${e.message}`);
            if (program.opts().json) respondAgent(false, null, e.message);
        }
    });

configCmd
    .command('reset')
    .description('Restore security specifications to factory defaults.')
    .action(() => {
        const specPath = path.join(__dirname, '..', 'backend', 'scanner', 'rules', 'sentinel-spec.json');
        const defaultPath = path.join(__dirname, '..', 'backend', 'scanner', 'rules', 'sentinel-spec.default.json');
        
        try {
            if (fs.existsSync(defaultPath)) {
                fs.copyFileSync(defaultPath, specPath);
                console.log('✅ Security specifications restored to factory defaults.');
                if (program.opts().json) respondAgent(true, { status: 'restored' });
            } else {
                throw new Error('Default specification backup not found.');
            }
        } catch (e) {
            console.error(`❌ Reset failed: ${e.message}`);
            if (program.opts().json) respondAgent(false, null, e.message);
        }
    });

// ─── sentinel status ───
program
    .command('status')
    .description('Show security status of all monitored repositories.')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        if (repos.length === 0) {
            console.log('📭 No repositories linked yet. Use "sentinel link <path> <owner/repo>" to get started.');
            if (program.opts().json) respondAgent(true, { repositories: [], total: 0 });
            return;
        }
        const summary = repos.map(r => ({
            id: r.id,
            name: r.github_full_name,
            path: r.local_path || null,
            status: r.status || 'UNKNOWN',
            last_scan: r.last_scan_at || null
        }));
        const safe = summary.filter(r => r.status === 'SAFE').length;
        const infected = summary.filter(r => r.status === 'INFECTED').length;
        if (program.opts().json) {
            respondAgent(true, { repositories: summary, total: repos.length, safe, infected });
        } else {
            console.log(`\n🛡️  Sentinel Status — ${repos.length} repo(s) monitored\n`);
            summary.forEach(r => {
                const icon = r.status === 'SAFE' ? '🟢' : (r.status === 'INFECTED' ? '🔴' : '⚪');
                console.log(`  ${icon} ${r.name} [${r.status}]`);
            });
            console.log(`\n  Summary: ${safe} safe, ${infected} infected\n`);
        }
    });

// ─── sentinel link ───
program
    .command('link <path> <repo>')
    .description('Link a local directory to a GitHub repository for Sentinel monitoring.')
    .action((p, r) => {
        const db = require('../backend/lib/db');
        try {
            const resolvedPath = path.resolve(p);
            if (!fs.existsSync(resolvedPath)) {
                console.error(`❌ Path does not exist: ${resolvedPath}`);
                if (program.opts().json) respondAgent(false, null, `Path does not exist: ${resolvedPath}`);
                return;
            }
            const repoId = db.addRepository(resolvedPath, r);
            if (repoId) {
                db.updateRepoPath(repoId, resolvedPath);
                console.log(`✅ Linked "${r}" → ${resolvedPath}`);
                if (program.opts().json) respondAgent(true, { repo_id: repoId, github_name: r, local_path: resolvedPath });
            } else {
                console.error('❌ Failed to link. The repository may already exist.');
                if (program.opts().json) respondAgent(false, null, 'Failed to link repository');
            }
        } catch (e) {
            console.error(`❌ Error linking repository: ${e.message}`);
            if (program.opts().json) respondAgent(false, null, e.message);
        }
    });

// ─── sentinel list ───
program
    .command('list')
    .description('List all repositories monitored by Sentinel.')
    .action(() => {
        const db = require('../backend/lib/db');
        const repos = db.getRepositories();
        if (repos.length === 0) {
            console.log('📭 No repositories linked yet.');
            if (program.opts().json) respondAgent(true, { repositories: [] });
            return;
        }
        if (program.opts().json) {
            const data = repos.map(r => ({
                id: r.id,
                name: r.github_full_name,
                path: r.local_path || null,
                status: r.status || 'UNKNOWN'
            }));
            respondAgent(true, { repositories: data });
        } else {
            repos.forEach(r => {
                const icon = r.status === 'SAFE' ? '🟢' : (r.status === 'INFECTED' ? '🔴' : '⚪');
                console.log(`  ${icon} ${r.github_full_name} ${r.local_path ? '(' + r.local_path + ')' : ''}`);
            });
        }
    });

// Note: Manual PR remote scanner has been deprecated in favor of 'sentinel audit-prs'.
function run(args = process.argv) {
    if (args.length === 2) {
        console.log('\n================================================================');
        console.log('                 🛡️  SENTINEL SECURITY GUARDIAN               ');
        console.log('================================================================\n');
        console.log('¡Hola! Sentinel detectó que no ingresaste ningún comando.\n');
        console.log('👤 ¿ERES UN DESARROLLADOR HUMANO?');
        console.log('   Si quieres usar la interfaz gráfica (Dashboard Web), ejecuta:');
        console.log('   👉  sentinel open\n');
        console.log('🤖 ¿ERES UN AGENTE DE IA?');
        console.log('   Sentinel está optimizado para flujos automatizados.');
        console.log('   Usa la bandera --json al final de cualquier comando.');
        console.log('');
        console.log('   Comandos clave para Agentes:');
        console.log('   👉  sentinel scan <ruta> --json      (Análisis total con engine v3.6 adaptativo)');
        console.log('   👉  sentinel config view --json      (Consultar heurísticas actuales)');
        console.log('   👉  sentinel explain <file> --json   (Dump raw del ConfidenceScorer)\n');
        console.log('================================================================\n');
        process.exit(0);
    }
    program.parse(args);
}

module.exports = { run };

if (require.main === module) {
    run();
}
