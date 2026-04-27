#!/usr/bin/env node
// CLI Function for Electron Integration
const { program } = require('commander');
const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;

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
    const db = require('../../sentinel-core/lib/db');
    const gh = require('../../sentinel-core/lib/gh_bridge');
    const { scanFile } = require('../../sentinel-core/scanner/index');

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
    const gh = require('../../sentinel-core/lib/gh_bridge');
    const db = require('../../sentinel-core/lib/db');
    const scanner = require('../../sentinel-core/scanner/index'); // Reuse backend scanner
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
    .version('3.7.0')
    .description('Sentinel Security Guardian — Deterministic Decision Engine')
    .option('--json', 'Machine-readable output (JSON)')
    .option('--profile <name>', 'Decision profile: balanced, strict, dev', 'balanced')
    .option('--allow-external', 'Allow scanning paths outside current directory (DANGEROUS)', false)
    .option('--report <adapter=path>', 'Attach external reports (e.g. --report npm=audit.json)', (val, memo) => {
        const parts = val.split('=');
        const adapter = parts[0];
        const p = parts.slice(1).join('='); // Handle paths with '='
        memo.push({ adapter, path: p });
        return memo;
    }, [])
    .option('--no-color', 'Disable terminal colors (useful for log files/CI)')
    .hook('preAction', () => {
        // Ensure rules are loaded before any action that might use them
        const scanner = require('../../sentinel-core/scanner/index');
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
    .option('--profile <type>', 'Risk Profile: balanced, aggressive, or conservative', 'balanced')
    .option('--scan-mode <type>', 'Scan profile: DEFAULT, DEEP, or FORENSIC', 'DEFAULT')
    .action(async (targetPath, cmdOptions) => {
        const scanner = require('../../sentinel-core/scanner/index');
        const NpmAdapter = require('../../sentinel-core/scanner/aggregators/npm_adapter');
        const DecisionExplainer = require('../../sentinel-core/scanner/aggregators/decision_explainer');
        const Orchestrator = require('../../sentinel-core/scanner/gate_orchestrator');

        // Consolidate global and local options
        const globalOpts = program.opts();
        const options = { ...globalOpts, ...cmdOptions };
        
        const absPath = path.resolve(targetPath);
        const cwd = process.cwd();
        
        // Determine the scan root directory (for ownership & fingerprint)
        const absStats = fs.statSync(absPath, { throwIfNoEntry: false });
        const scanDir = (absStats && absStats.isFile()) ? path.dirname(absPath) : absPath;

        // Governance: Direct Boundary Check
        const relative = path.relative(cwd, absPath);
        const isOutside = relative.startsWith('..') || path.isAbsolute(relative);
        
        if (isOutside && !options.allowExternal) {
            console.error(pc.red(`\n\u274c Security Block: Sentinel scanning is restricted to the current directory hierarchy.`));
            console.error(pc.dim(`Target: ${absPath}\nCWD: ${cwd}\n`));
            console.error(`To scan external paths, use ${pc.bold('--allow-external')} (Liability disclaimer applies).`);
            process.exit(1);
        }

        // 0. Oracle: Resolve Ownership (Multi-Signal)
        const gh = require('../../sentinel-core/lib/gh_bridge');
        let ownershipResult = { authorized: true, confidence: 'HIGH', signals: {}, signalCount: 4 };
        let authUser = 'local';
        try {
            const auth = gh.checkAuth();
            authUser = auth.authenticated ? auth.username : 'anonymous';
            ownershipResult = gh.resolveOwnership(scanDir, auth);
        } catch {
            // Fail-closed: if ownership resolution fails, treat as unauthorized
            ownershipResult = { authorized: false, confidence: 'LOW', signals: {}, signalCount: 0 };
        }

        const isAuthorized = ownershipResult.authorized;

        if (!isAuthorized && !options.ci && !options.json) {
            console.log(pc.bgYellow(pc.black('\n  \u26a0  RESTRICTED INTELLIGENCE MODE  ')));
            console.log(pc.yellow('Current repository is not verified as authorized.'));
            console.log(pc.dim('Analysis logic has been throttled to prevent intellectual property leakage.'));
            console.log(pc.dim(`Session ID: ${repoFingerprint.substring(0, 8)}... (Logged)\n`));
        }

        // 0b. Oracle: Generate Hardened Fingerprint
        const repoFingerprint = scanner.generateHardenedFingerprint(scanDir);


        let fileList = [];
        const stats = fs.statSync(absPath, { throwIfNoEntry: false });
        if (stats && stats.isDirectory()) {
            fileList = fs.readdirSync(absPath);
        } else if (stats) {
            fileList = [absPath];
        }

        // 1. Auto-Escalation Logic (Sentinel Gates)
        const gateInfo = Orchestrator.resolveGateLevel(fileList);
        const activeLevel = options.gateLevel || (options.fast ? 0 : gateInfo.level);
        
        // 2. Load External Signals
        let externalSignals = [];
        if (options.report && options.report.length > 0) {
            options.report.forEach(r => {
                try {
                    const reportPath = path.resolve(r.path);
                    if (r.adapter === 'npm' && fs.existsSync(reportPath)) {
                        const content = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
                        externalSignals.push(...NpmAdapter.mapAudit(content));
                    }
                } catch (e) {
                    console.error(`[CLI] Error loading external report ${r.path}:`, e.message);
                }
            });
        }

        // 3. Perform Primary Scan
        const scanOptions = {
            mode: options.mode,
            gateLevel: activeLevel,
            profile: options.scanMode?.toUpperCase() || 'DEFAULT'
        };

        let results;
        if (stats && stats.isDirectory()) {
            results = await scanner.scanDirectory(absPath, null, 10, scanOptions);
        } else if (stats && stats.isFile()) {
            const content = await fsPromises.readFile(absPath, 'utf8');
            scanner.loadRules();
            const scan = await scanner.scanFile(path.basename(absPath), content, null, scanOptions);
            scan.alerts.forEach(a => { a._file = path.basename(absPath); a._fullPath = absPath; });
            results = {
                version: "3.7.1",
                rulepack_version: "2026.04",
                filesScanned: 1,
                skipped: { binary: 0, excluded: 0, large: 0, unsupported: 0, cached: 0 },
                rawAlerts: scan.alerts,
                threats: scan.alerts.length,
                performance: { durationMs: 0, filesPerSec: 0 }
            };
        } else {
            console.error(`\u274c Path not found: ${targetPath}`);
            process.exit(1);
        }

        // 4. Finalize Verdict with Oracle Context
        const oracleCtx = { isAuthorized, fingerprint: repoFingerprint, user: authUser };
        scanner.finalizeVerdict(results, externalSignals, options.profile, oracleCtx);

        // 5. Forensic Audit Log
        scanner.logScanAudit({
            fingerprint: repoFingerprint,
            ownershipStatus: isAuthorized ? 'authorized' : 'unauthorized',
            riskBand: results.riskBand?.name || 'UNKNOWN',
            scanPath: absPath, user: authUser
        });

        // 6. Strategic Deterrence & Final Display (v3.7.3 - Policy Driven)
        if (!options.ci && !options.json) {
            
            // A. Lockdown Alert
            if (results.lockdown) {
                console.log(pc.bgRed(pc.white('\n  \u26a0  SYSTEM PROTECTION LOCK ACTIVATED  ')));
                console.log(pc.red('Multiple exfiltration patterns detected. High-fidelity output disabled.'));
                console.log(pc.dim(`Verified Audit Trail ID: ${results.traceId}\n`));
                process.exit(1);
            }

            // B. Governance Context
            console.log(pc.cyan('\n\u2696\ufe0f  GOVERNANCE POLICY'));
            console.log(`${pc.dim('Active Policy:')} ${results.policy?.name || 'Standard'}`);
            console.log(`${pc.dim('Exposure Level:')} ${results.policy?.exposure?.toUpperCase() || 'RESTRICTED'}`);
            console.log(`${pc.dim('Audit Status:')} ${results.policy?.auditStatus || 'ENABLED'}`);

            // C. Dynamic Latency
            if (results.delayMs > 0) {
                console.log(pc.yellow('\n\u23f3  ADAPTIVE ANALYSIS THROTTLING'));
                console.log(pc.dim(`Introducing protective latency (${(results.delayMs/1000).toFixed(1)}s) per organizational policy...`));
                await new Promise(r => setTimeout(r, results.delayMs));
            }

            // D. Decision Banner & Rationale
            console.log(DecisionExplainer.formatBanner(results.decisionVerdict, results.activeProfile));
            console.log(DecisionExplainer.explain(results));

            // E. Verified Audit Trail
            console.log(pc.cyan('\n\ud83d\udee1\ufe0f  VERIFIED AUDIT TRAIL'));
            const trustLabels = ['RESTRICTED', 'PARTNER / LIMITED', 'AUTHORIZED'];
            const trustColor = results.trustLevel === 2 ? pc.green : (results.trustLevel === 1 ? pc.blue : pc.yellow);
            
            console.log(`${pc.dim('Trust Level:')} ${trustColor(trustLabels[results.trustLevel])}`);
            console.log(`${pc.dim('Audit Trail ID:')} ${results.traceId}`);
            console.log(`${pc.dim('Integrity Sig:')} ${results.report_signature.substring(0, 32)}...`);
            
            // F. Institutional Legal Disclaimer
            console.log(pc.dim('\n LEGAL NOTICE: This session is subject to audit logging under organizational '));
            console.log(pc.dim(" policy. Unauthorized reverse engineering or manipulation of Sentinel's "));
            console.log(pc.dim(' intelligence outputs may violate Intellectual Property and Usage terms.\n'));
        }

        if (options.json) {
            process.stdout.write(JSON.stringify(results, null, 2) + '\n');
            process.exit(results.decisionVerdict === 'BLOCK' ? 1 : 0);
        }

        if (results.decisionVerdict === 'BLOCK') process.exit(1);
    });

// ─── sentinel install (Dependency Trust Engine v3.0) ───
program
    .command('install')
    .description('Verify and install a package through the Sentinel Policy Firewall.')
    .argument('<adapter>', 'Package manager (npm, pip, docker)')
    .argument('<package>', 'Package name or image reference')
    .option('--sandbox', 'Force remote sandbox verification')
    .option('--force', 'Bypass Trust Cache and re-evaluate')
    .option('--advisory', 'Advisory mode: warn but never block')
    .action(async (adapter, pkgName, options) => {
        const Shield = require('../../sentinel-core/scanner/supply_chain_shield');
        const Policy = require('../../sentinel-core/scanner/policy_engine');
        const gh = require('../../sentinel-core/lib/gh_bridge');

        let isAuthorized = false;
        try {
            const auth = gh.checkAuth();
            isAuthorized = gh.resolveOwnership(process.cwd(), auth).authorized;
        } catch (e) {}

        const isAdvisory = options.advisory || !Policy.shouldEnforceBlock();
        const modeLabel = isAdvisory ? pc.blue('[ADVISORY]') : pc.red('[STRICT]');

        process.stdout.write(pc.cyan(`\n\ud83d\udee1\ufe0f  SENTINEL FIREWALL ${modeLabel}: Evaluating '${pkgName}'...`));

        if (options.force) Shield.getTrustCache()._cache[`${adapter}:${pkgName}`] = undefined;
        const preScan = await Shield.preScanManifest(adapter, pkgName);

        if (preScan.fromCache) {
            process.stdout.write(pc.dim(` [cache:${preScan.cacheHash}]\n`));
        } else {
            process.stdout.write('\n');
        }

        // ── BLOCK verdict ─────────────────────────────────────────────
        if (preScan.verdict === 'BLOCK') {
            if (isAdvisory) {
                // Advisory: warn loudly, but proceed
                console.log(pc.bgYellow(pc.black('  \u26a0  RISK DETECTED — PROCEEDING IN ADVISORY MODE  ')));
                if (isAuthorized) {
                    preScan.signals.forEach(s => {
                        console.log(`  ${pc.yellow('\u2022')} ${pc.bold(s.type)} [${s.category}]`);
                        console.log(`    ${pc.dim(s.description)}`);
                    });
                }
                console.log(pc.yellow('\n  In STRICT mode (CI/CD), this installation would be blocked.'));
                console.log(pc.dim(`  Audit Trail recorded. Consider: sentinel verify-pkg ${adapter} ${pkgName} --sandbox\n`));
                // Proceed anyway
                Shield.executeInstall(adapter, pkgName);
                return;
            }

            // Strict: hard block
            console.log(pc.bgRed(pc.white('  \u26d4  INSTALLATION BLOCKED BY POLICY  ')));
            if (isAuthorized) {
                preScan.signals.forEach(s => {
                    console.log(`  ${pc.red('\u2022')} ${pc.bold(s.type)} [${s.category}]`);
                    console.log(`    ${pc.dim(s.description)}`);
                });
            } else {
                console.log(pc.dim('\nThis package violates organizational security policies.'));
                console.log(pc.dim('Specific threat intelligence is restricted per policy.'));
            }
            console.log(pc.cyan('\nSAFE ALTERNATIVE: Remote sandbox verification'));
            console.log(pc.bold(`  sentinel verify-pkg ${adapter} ${pkgName} --sandbox\n`));
            process.exit(1);
        }

        // ── SUSPICIOUS verdict ────────────────────────────────────────
        if (preScan.verdict === 'SUSPICIOUS' || options.sandbox) {
            console.log(pc.bgYellow(pc.black('  \u26a0  PACKAGE FLAGGED — SANDBOX RECOMMENDED  ')));
            if (isAuthorized) {
                preScan.signals.forEach(s => {
                    console.log(`  ${pc.yellow('\u2022')} ${pc.bold(s.type)} [${s.category}]`);
                    console.log(`    ${pc.dim(s.description)}`);
                });
            }
            console.log(pc.dim(`\nAudit Trail recorded. Use 'sentinel verify-pkg ${adapter} ${pkgName} --sandbox' for confirmation.\n`));
        } else {
            console.log(pc.green('\u2713 SAFE — Policy Authorization Granted.'));
        }

        Shield.executeInstall(adapter, pkgName);
    });

// ─── sentinel verify-pkg (Cloud Sandbox Orchestrator) ───
program
    .command('verify-pkg')
    .description('Verify a package behavior in a remote cloud sandbox.')
    .argument('<adapter>', 'Package manager')
    .argument('<package>', 'Package name')
    .action((adapter, pkgName) => {
        const Shield = require('../../sentinel-core/scanner/supply_chain_shield');
        console.log(pc.cyan(`\n\ud83d\udce6  ORCHESTRATING CLOUD SANDBOX: ${adapter}://${pkgName}`));
        const workflow = Shield.generateSandboxWorkflow(adapter, pkgName);
        const workflowPath = path.join(process.cwd(), '.github', 'workflows', 'sentinel-sandbox.yml');
        if (!fs.existsSync(path.dirname(workflowPath))) fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
        fs.writeFileSync(workflowPath, workflow);
        console.log(pc.green('\u2713 Sandbox workflow generated.'));
        console.log(pc.dim('  Path: .github/workflows/sentinel-sandbox.yml'));
        console.log('\nTrigger with:');
        console.log(pc.bold('  gh workflow run sentinel-sandbox.yml\n'));
    });

// ─── sentinel guard (OS Interception Layer) ───
program
    .command('guard')
    .description('Manage Sentinel Guard — OS-level package manager interception.')
    .argument('<action>', 'enable | disable | status')
    .action((action) => {
        const Guard = require('./guard');

        if (action === 'status') {
            const active = Guard.isGuardEnabled();
            console.log(`\n\ud83d\udee1\ufe0f  Sentinel Guard: ${active ? pc.green('ACTIVE') : pc.yellow('INACTIVE')}`);
            if (active) {
                console.log(pc.dim(`  Intercepting: ${Guard.SUPPORTED_MANAGERS.join(', ')}`));
                console.log(pc.dim(`  Profile: ${Guard.getShellProfilePath()}`));
            }
            return;
        }

        if (action === 'enable') {
            const result = Guard.enableGuard();
            if (!result.success) {
                console.log(pc.yellow(`\u26a0  ${result.reason}`));
                return;
            }
            console.log(pc.green('\n\u2713 Sentinel Guard ENABLED'));
            console.log(pc.dim(`  Profile modified: ${result.profilePath}`));
            console.log(pc.dim(`  Intercepting: ${result.managers.join(', ')}`));
            console.log(pc.cyan('\nRestart your shell or run:'));
            console.log(pc.bold(`  source ${result.profilePath}\n`));
            console.log(pc.dim('Every package installation will now pass through the Sentinel Firewall.'));
            return;
        }

        if (action === 'disable') {
            const result = Guard.disableGuard();
            console.log(result.success
                ? pc.yellow('\n\u26a0  Sentinel Guard DISABLED. Package managers restored.')
                : pc.red(`\u274c ${result.reason}`)
            );
            return;
        }

        console.log(pc.red(`Unknown action '${action}'. Use: enable | disable | status`));
    });

// ─── sentinel trust (Trust Cache Management) ───
program
    .command('trust')
    .description('Manage the Sentinel Trust Cache for instant package verification.')
    .argument('<action>', 'add | block | list | clear')
    .argument('[package]', 'Package name (for add/block)')
    .option('--adapter <mgr>', 'Package manager (npm, pip, cargo)', 'npm')
    .action((action, pkgName, options) => {
        const Shield = require('../../sentinel-core/scanner/supply_chain_shield');
        const cache  = Shield.getTrustCache();

        if (action === 'add') {
            if (!pkgName) return console.log(pc.red('Package name required.'));
            cache.markTrusted(options.adapter, pkgName);
            console.log(pc.green(`\u2713 '${options.adapter}:${pkgName}' marked as TRUSTED`));
            console.log(pc.dim('  Future installations will bypass security evaluation.'));
            return;
        }

        if (action === 'block') {
            if (!pkgName) return console.log(pc.red('Package name required.'));
            cache.markBlocked(options.adapter, pkgName);
            console.log(pc.red(`\u26d4 '${options.adapter}:${pkgName}' permanently BLOCKED`));
            return;
        }

        if (action === 'list') {
            const entries = cache.all();
            const keys = Object.keys(entries);
            if (keys.length === 0) return console.log(pc.dim('Trust Cache is empty.'));
            console.log(pc.cyan(`\n\ud83d\udcc6  TRUST CACHE (${keys.length} entries)\n`));
            for (const [key, val] of Object.entries(entries)) {
                const color = val.verdict === 'TRUSTED' ? pc.green : (val.verdict === 'BLOCKED' ? pc.red : pc.yellow);
                const age   = Math.floor((Date.now() - val.ts) / 86400000);
                console.log(`  ${color(val.verdict.padEnd(10))} ${key.padEnd(30)} ${pc.dim(`${age}d ago  [${val.hash}]`)}`);
            }
            console.log('');
            return;
        }

        if (action === 'clear') {
            cache._cache = {};
            cache._save();
            console.log(pc.yellow('\u26a0  Trust Cache cleared. All packages will be re-evaluated.'));
            return;
        }

        console.log(pc.red(`Unknown action '${action}'. Use: add | block | list | clear`));
    });

// ─── sentinel explain (v3.6) ───
program
    .command('explain')
    .description('Explain the logic and heuristics behind a flagged file.')
    .argument('<file>', 'File path to explain')
    .action((file) => {
        const scanner = require('../../sentinel-core/scanner/index');
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
        const scanner = require('../../sentinel-core/scanner/index');
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

// ─── sentinel hub (Interactive GitHub Mode v3.8) ───
program
    .command('hub')
    .description('Launch the Interactive Sentinel Hub (GitHub OAuth, Repo Selection, PR Inspection)')
    .action(async () => {
        const { startInteractiveHub } = require('./interactive');
        await startInteractiveHub();
    });

// ─── sentinel check-classified (Pre-commit hook backend) ───
program
    .command('check-classified')
    .description('Verify staged files against classified DB (pre-commit)')
    .argument('<path>', 'Repository path')
    .action((repoPath) => {
        const { checkClassifiedHook } = require('./classify');
        process.exit(checkClassifiedHook(repoPath));
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
        const scanner = require('../../sentinel-core/scanner/index');
        const Orchestrator = require('../../sentinel-core/scanner/gate_orchestrator');
        
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
        const db = require('../../sentinel-core/lib/db');
        const gh = require('../../sentinel-core/lib/gh_bridge');
        const ci = require('../../sentinel-core/lib/ci_sandbox');
        
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
        const db = require('../../sentinel-core/lib/db');
        const gh = require('../../sentinel-core/lib/gh_bridge');
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
        const db = require('../../sentinel-core/lib/db');
        const gh = require('../../sentinel-core/lib/gh_bridge');
        const ci = require('../../sentinel-core/lib/ci_sandbox');
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
        const db = require('../../sentinel-core/lib/db');
        const gh = require('../../sentinel-core/lib/gh_bridge');
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
            const db = require('../../sentinel-core/lib/db');
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
        const db = require('../../sentinel-core/lib/db');
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
        const db = require('../../sentinel-core/lib/db');
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
        const db = require('../../sentinel-core/lib/db');
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
        const db = require('../../sentinel-core/lib/db');
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

// ─── PR Firewall Commands (v3.8) ───

program
    .command('policy <action> [path]')
    .description('Manage repository protection policies (add, list, remove, protect)')
    .option('--rule <type>', 'Rule type (no-modify, require-review)', 'no-modify')
    .option('--mode <type>', 'Enforcement mode (strict, advisory)', 'strict')
    .option('--reviewers <list>', 'Comma-separated list of required reviewers')
    .action((action, targetPath, options) => {
        const prEngine = require('../../sentinel-core/scanner/pr_policy_engine');
        const repoPath = process.cwd();

        try {
            if (action === 'protect') {
                if (!targetPath) throw new Error('Path is required for protect action.');
                prEngine.saveRule(repoPath, { path: targetPath, rule: 'no-modify', mode: 'strict' });
                console.log(`\x1b[32m\u2713\x1b[0m Protected ${targetPath} (Strict no-modify policy applied).`);
            } else if (action === 'add') {
                if (!targetPath) throw new Error('Path is required for add action. Usage: sentinel policy add <path> [options]');
                const rule = { path: targetPath, rule: options.rule, mode: options.mode };
                if (options.reviewers) rule.reviewers = options.reviewers;
                prEngine.saveRule(repoPath, rule);
                console.log(`\x1b[32m\u2713\x1b[0m Policy rule added for ${targetPath}.`);
            } else if (action === 'remove') {
                if (!targetPath) throw new Error('Path is required for remove action.');
                const removed = prEngine.removeRule(repoPath, targetPath);
                if (removed) console.log(`\x1b[32m\u2713\x1b[0m Policy rule removed for ${targetPath}.`);
                else console.log(`No policy rule found for ${targetPath}.`);
            } else if (action === 'list') {
                const policies = prEngine.loadPolicies(repoPath);
                console.log(`\n\x1b[36m🛡️  Sentinel Policy Rules (Schema v${policies.policy_schema_version})\x1b[0m\n`);
                if (!policies.rules || policies.rules.length === 0) {
                    console.log('  No policies defined. Use `sentinel policy protect <path>` to get started.');
                } else {
                    policies.rules.forEach(r => {
                        console.log(`  \x1b[33m${r.path}\x1b[0m`);
                        console.log(`    Rule: \x1b[1m${r.rule}\x1b[0m (${r.mode})`);
                        if (r.reviewers) console.log(`    Reviewers: ${r.reviewers}`);
                    });
                }
                console.log();
            } else {
                console.error(`Unknown action: ${action}. Use add, list, remove, or protect.`);
            }
        } catch (e) {
            console.error(`\x1b[31mError:\x1b[0m ${e.message}`);
        }
    });

program
    .command('pr <action> [repo] [prNumber]')
    .description('Manage and enforce Pull Request policies (scan, hook)')
    .option('--ci', 'Run in CI environment mode (enforces Checks API)')
    .action(async (action, repoFullName, prNumberStr, options) => {
        const gh = require('../../sentinel-core/lib/gh_bridge');
        const prEngine = require('../../sentinel-core/scanner/pr_policy_engine');
        const Shield = require('../../sentinel-core/scanner/supply_chain_shield');
        const fs = require('fs');

        if (action === 'hook') {
            const destPath = path.join(process.cwd(), '.github', 'workflows', 'sentinel-pr-firewall.yml');
            const templatePath = path.join(__dirname, '..', 'backend', 'templates', 'sentinel-pr-firewall.yml');
            
            if (!fs.existsSync(path.dirname(destPath))) {
                fs.mkdirSync(path.dirname(destPath), { recursive: true });
            }
            fs.copyFileSync(templatePath, destPath);
            console.log(`\x1b[32m\u2713\x1b[0m PR Firewall GitHub Action installed at: .github/workflows/sentinel-pr-firewall.yml`);
            console.log(`Commit and push this file to enable automatic PR policy enforcement.`);
            return;
        }

        if (action === 'scan') {
            if (!repoFullName || !prNumberStr) {
                console.error("Usage: sentinel pr scan <owner/repo> <pr-number>");
                process.exit(1);
            }

            const prNumber = parseInt(prNumberStr, 10);
            console.log(`\n\x1b[36m🛡️  Sentinel PR Firewall: Scanning PR #${prNumber} in ${repoFullName}...\x1b[0m`);

            // 1. Get PR Files
            const files = gh.getPRFiles(repoFullName, prNumber);
            if (files === null) {
                console.error("\x1b[31m\u274c Invalid repo target. Expected owner/repo with GitHub access.\x1b[0m\n");
                process.exit(1);
            }
            if (files.length === 0) {
                console.log("No files modified in this PR or unable to fetch diff.");
                return;
            }
            console.log(`\x1b[2mFound ${files.length} modified file(s).\x1b[0m`);

            // 2. Playbook Discovery
            const SPL = require('../../sentinel-core/spl/index');
            const policyDir = path.join(process.cwd(), '.sentinel', 'policies');
            const playbooks = fs.existsSync(policyDir) ? 
                fs.readdirSync(policyDir).filter(f => f.endsWith('.sentinel')) : [];

            let finalVerdict = 'allow';
            let summary = '';
            let details = "### Sentinel Security Intelligence Report\n\n";

            if (playbooks.length > 0) {
                console.log(`\x1b[36m\ud83d\udcc1 Found ${playbooks.length} playbook(s). Executing...\x1b[0m`);
                
                // Context for playbooks
                const context = {
                    event: { type: 'pr', changedFiles: files, pr_number: prNumber },
                    repo: { fullName: repoFullName, path: process.cwd(), authorized: true }
                };

                for (const pbFile of playbooks) {
                    const source = fs.readFileSync(path.join(policyDir, pbFile), 'utf8');
                    try {
                        const result = SPL.run(source, context);
                        
                        // Aggregate verdict (any block → block)
                        if (result.results.some(r => r.verdict === 'block')) finalVerdict = 'block';
                        else if (result.results.some(r => r.verdict === 'review') && finalVerdict !== 'block') finalVerdict = 'review';

                        // Add to details
                        details += SPL.explain(result, { markdown: true });
                    } catch (e) {
                        console.error(`\x1b[31m\u26a0 Error in playbook ${pbFile}: ${e.message}\x1b[0m`);
                    }
                }
            } else {
                // Fallback to static PR Policy Engine
                console.log(`\x1b[2mNo playbooks found. Using static policy engine.\x1b[0m`);
                prEngine.loadPolicies(process.cwd());
                const result = prEngine.evaluateFiles(files);
                
                finalVerdict = result.verdict === 'FAIL' ? 'block' : (result.verdict === 'ADVISORY' ? 'review' : 'allow');
                
                if (result.violations.length > 0) {
                    details += "#### Policy Violations Detected:\n\n";
                    result.violations.forEach(v => {
                        details += `- **${v.mode.toUpperCase()}** \`${v.file}\`: ${v.message} (Rule: ${v.rule})\n`;
                    });
                } else {
                    details += "✅ No policy violations detected.\n";
                }
            }

            // 3. Final Formatting
            let conclusion = finalVerdict === 'block' ? 'failure' : (finalVerdict === 'review' ? 'neutral' : 'success');
            let statusLog = finalVerdict === 'block' ? '\x1b[31mBLOCK\x1b[0m' : (finalVerdict === 'review' ? '\x1b[33mREVIEW\x1b[0m' : '\x1b[32mALLOW\x1b[0m');
            summary = finalVerdict === 'block' ? "Sentinel blocked this PR due to security policy violations." : "Sentinel security evaluation completed.";

            console.log(`\n\x1b[1mVerdict: ${statusLog}\x1b[0m`);

            // 4. Submit to GitHub Checks API
            const sha = gh.getPRHeadSha(repoFullName, prNumber);
            if (sha) {
                const posted = gh.createCheckRun(
                    repoFullName, 
                    sha, 
                    'Sentinel PR Firewall', 
                    'completed', 
                    conclusion, 
                    summary, 
                    details, 
                    options.ci
                );
                if (posted) console.log(`\x1b[32m\u2713 GitHub Check Run created.\x1b[0m`);
            } else {
                console.warn("\x1b[33mUnable to fetch PR HEAD SHA. Check Run skipped.\x1b[0m");
            }

            if (finalVerdict === 'block' && options.ci) {
                process.exit(1);
            }
            return;
        }

        console.error("Unknown action. Use 'scan' or 'hook'.");
    });

// ─── Sentinel Playbook Language (SPL v0.1) ───

program
    .command('playbook <action> [file] [extra]')
    .description('Run, validate, or compile Sentinel Playbook (.sentinel) files')
    .option('--context <json>', 'JSON string with runtime context for execution')
    .action(async (action, file, extra, options) => {
        const SPL = require('../../sentinel-core/spl/index');

        if (action === 'validate') {
            if (!file) { console.error("Usage: sentinel playbook validate <file.sentinel>"); process.exit(1); }
            const source = fs.readFileSync(path.resolve(file), 'utf8');
            const result = SPL.validate(source);

            if (result.valid) {
                console.log(`\x1b[32m\u2713 Playbook is valid.\x1b[0m`);
                if (result.warnings.length > 0) {
                    result.warnings.forEach(w => console.log(`  \x1b[33m\u26a0 ${w}\x1b[0m`));
                }
            } else {
                console.error(`\x1b[31m\u274c Playbook has errors:\x1b[0m`);
                result.errors.forEach(e => console.error(`  ${e}`));
                if (result.warnings.length > 0) {
                    result.warnings.forEach(w => console.log(`  \x1b[33m\u26a0 ${w}\x1b[0m`));
                }
                process.exit(1);
            }
            return;
        }

        if (action === 'compile') {
            if (!file) { console.error("Usage: sentinel playbook compile <file.sentinel>"); process.exit(1); }
            const source = fs.readFileSync(path.resolve(file), 'utf8');
            try {
                const { compiled, warnings } = SPL.compile(source);
                if (warnings.length > 0) {
                    warnings.forEach(w => console.error(`\x1b[33m\u26a0 ${w}\x1b[0m`));
                }
                process.stdout.write(JSON.stringify(compiled, null, 2) + '\n');
            } catch (e) {
                console.error(`\x1b[31m\u274c ${e.message}\x1b[0m`);
                process.exit(1);
            }
            return;
        }

        if (action === 'run') {
            if (!file) { console.error("Usage: sentinel playbook run <file.sentinel> [--context '{...}']"); process.exit(1); }
            const source = fs.readFileSync(path.resolve(file), 'utf8');

            let context = {};
            if (options.context) {
                try { context = JSON.parse(options.context); }
                catch (e) { console.error(`\x1b[31m\u274c Invalid --context JSON: ${e.message}\x1b[0m`); process.exit(1); }
            }

            try {
                console.log(`\n\x1b[36m\ud83d\udee1\ufe0f  Sentinel Playbook Engine v0.1\x1b[0m`);
                console.log(`\x1b[2mFile: ${file}\x1b[0m\n`);

                const { results, warnings } = await SPL.run(source, context);

                if (warnings.length > 0) {
                    console.log('\x1b[33mWarnings:\x1b[0m');
                    warnings.forEach(w => console.log(`  \u26a0 ${w}`));
                    console.log();
                }

                let exitCode = 0;
                results.forEach(r => {
                    const icon = r.verdict === 'block' ? '\x1b[31m\u26d4' :
                                 r.verdict === 'allow' ? '\x1b[32m\u2713' :
                                 r.verdict === 'sandbox' ? '\x1b[33m\ud83d\udce6' : '\x1b[36m\u2139';
                    console.log(`${icon} Workflow "${r.workflow}" → ${r.verdict.toUpperCase()}\x1b[0m`);
                    console.log(`  \x1b[2mProfile: ${r.profile} | Target: ${r.target?.kind || 'none'}\x1b[0m`);

                    // Show execution log summary
                    const engines = r.log.filter(l => l.type === 'engine').map(l => l.engine);
                    const actions = r.log.filter(l => l.type === 'action').map(l => l.action);
                    if (engines.length) console.log(`  \x1b[2mEngines: ${engines.join(', ')}\x1b[0m`);
                    if (actions.length) console.log(`  \x1b[2mActions: ${actions.join(', ')}\x1b[0m`);
                    console.log();

                    if (r.verdict === 'block') exitCode = 1;
                });

                process.exit(exitCode);
            } catch (e) {
                console.error(`\x1b[31m\u274c ${e.message}\x1b[0m`);
                process.exit(1);
            }
            return;
        }

        if (action === 'explain') {
            if (!file) { console.error("Usage: sentinel playbook explain <file.sentinel> [--context '{...}']"); process.exit(1); }
            const source = fs.readFileSync(path.resolve(file), 'utf8');

            let context = {};
            if (options.context) {
                try { context = JSON.parse(options.context); }
                catch (e) { console.error(`\x1b[31m\u274c Invalid --context JSON: ${e.message}\x1b[0m`); process.exit(1); }
            }

            try {
                const executionResult = await SPL.run(source, context);
                const justification = SPL.explain(executionResult);
                process.stdout.write(justification + '\n');
            } catch (e) {
                console.error(`\x1b[31m\u274c ${e.message}\x1b[0m`);
                process.exit(1);
            }
            return;
        }

        if (action === 'pack') {
            const subAction = file; 
            const name = extra;

            if (subAction === 'install') {
                if (!name || name === 'install') { console.error("Usage: sentinel playbook pack install <fintech|supply-chain|ci-cd>"); process.exit(1); }
                
                const packFileMap = {
                    'fintech': 'fintech-compliance.sentinel',
                    'supply-chain': 'supply-chain-hardened.sentinel',
                    'ci-cd': 'ci-cd-lockdown.sentinel'
                };

                const sourceFile = packFileMap[name];
                if (!sourceFile) { console.error(`Unknown pack: ${name}. Available: fintech, supply-chain, ci-cd`); process.exit(1); }

                const sourcePath = path.join(__dirname, '../../sentinel-core/templates/packs', sourceFile);
                const destPath = path.join(process.cwd(), '.sentinel', 'policies', sourceFile);

                try {
                    if (!fs.existsSync(path.dirname(destPath))) fs.mkdirSync(path.dirname(destPath), { recursive: true });
                    fs.copyFileSync(sourcePath, destPath);
                    console.log(`\x1b[32m\u2713 Policy Pack '${name}' installed to ${destPath}\x1b[0m`);
                    console.log(`\x1b[2mRun it with: sentinel playbook run .sentinel/policies/${sourceFile}\x1b[0m`);
                } catch (e) {
                    console.error(`\x1b[31m\u274c Failed to install pack: ${e.message}\x1b[0m`);
                    process.exit(1);
                }
                return;
            }
            
            console.error("Unknown sub-action. Use 'sentinel playbook pack install <name>'.");
            return;
        }

        if (action === 'simulate') {
            if (!file) { console.error("Usage: sentinel playbook simulate <file.sentinel> [--context '{...}']"); process.exit(1); }
            const source = fs.readFileSync(path.resolve(file), 'utf8');

            let context = {};
            if (options.context) {
                try { context = JSON.parse(options.context); }
                catch (e) { console.error(`\x1b[31m\u274c Invalid --context JSON: ${e.message}\x1b[0m`); process.exit(1); }
            }

            try {
                const impact = await SPL.simulate(source, context);
                const report = SPL.formatSimulation(impact);
                process.stdout.write(report + '\n');
            } catch (e) {
                console.error(`\x1b[31m\u274c ${e.message}\x1b[0m`);
                process.exit(1);
            }
            return;
        }

        console.error("Unknown action. Use 'run', 'validate', 'compile', 'explain', 'pack', or 'simulate'.");
    });

// ─── Sentinel Global Intelligence Sync (Phase 4) ───

program
    .command('sync <action>')
    .description('Synchronize local Risk Graph with Global Intelligence Network')
    .action(async (action) => {
        const syncManager = require('../../sentinel-core/scanner/aggregators/sync_manager');

        if (action === 'push') {
            console.log("Starting local intelligence export...");
            const result = await syncManager.push();
            if (result.success) {
                console.log(`\x1b[32m\u2713 Successfully synchronized ${result.count} local signals to the network.\x1b[0m`);
            }
            return;
        }

        if (action === 'pull') {
            console.log("Fetching global intelligence updates...");
            const result = await syncManager.pull();
            if (result.success) {
                console.log(`\x1b[32m\u2713 Merged ${result.count} verified threat signals into the local Risk Graph.\x1b[0m`);
            }
            return;
        }

        if (action === 'status') {
            const riskGraph = require('../../sentinel-core/scanner/aggregators/risk_graph');
            const stats = {
                nodes: Object.values(riskGraph.nodes).reduce((acc, val) => acc + Object.keys(val).length, 0),
                edges: riskGraph.edges.length,
                lastSync: syncManager.lastSync || 'Never'
            };
            console.log(`\n\x1b[1mSentinel Intelligence Status:\x1b[0m`);
            console.log(`  Local Graph Size: ${stats.nodes} nodes, ${stats.edges} edges`);
            console.log(`  Last Global Sync: ${stats.lastSync}`);
            return;
        }

        console.error("Unknown action. Use 'push', 'pull', or 'status'.");
    });

// ─── Sentinel Risk Graph (Phase 3) ───

program
    .command('graph <action> [target]')
    .description('Inspect the Sentinel Risk Graph (Reputation & Correlation)')
    .action((action, target) => {
        const riskGraph = require('../../sentinel-core/scanner/aggregators/risk_graph');

        if (action === 'stats') {
            if (!target) { console.error("Usage: sentinel graph stats <package:name|repository:name>"); process.exit(1); }
            
            const [type, id] = target.split(':');
            if (!id) { console.error("Invalid target format. Use type:id (e.g., package:axios)"); process.exit(1); }

            if (type === 'package') {
                const stats = riskGraph.getPackageStats(id);
                console.log(`\n\x1b[1mRisk Graph Stats: Package [${id}]\x1b[0m`);
                console.log(`  Seen Count:   ${stats.seen_count}`);
                console.log(`  Block Count:  ${stats.block_count}`);
                console.log(`  Risk Score:   ${stats.risk_score}`);
                console.log(`  Last Seen:    ${stats.last_seen || 'Never'}`);

                const spikes = riskGraph.getTemporalSpikes(`package:${id}`, 24);
                console.log(`  Temporal Spikes (24h): ${spikes.count}`);
            } else {
                console.log(`Stats for ${type} not yet implemented.`);
            }
            return;
        }

        if (action === 'edges') {
            if (!target) { console.error("Usage: sentinel graph edges <type:id>"); process.exit(1); }
            const edges = riskGraph.getRelatedEdges(target);
            console.log(`\n\x1b[1mRelated Edges for [${target}]:\x1b[0m`);
            edges.forEach(e => {
                console.log(`  ${e.from} ──[${e.type}]──> ${e.to} (${e.timestamp})`);
            });
            return;
        }

        console.error("Unknown action. Use 'stats' or 'edges'.");
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
