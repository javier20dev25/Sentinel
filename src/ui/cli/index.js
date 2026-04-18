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
 * Shared logic for local analysis (used by 'analyze', 'heal', and 'prepush').
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

    const results = scanFile(options.isHook ? 'outgoing.diff' : 'local.diff', diff);

    return {
        success: true,
        alerts: results.alerts,
        violations,
        repo
    };
}

// ─── CLI COMMAND DEFINITIONS ───

program
    .version('1.0.0')
    .description('Sentinel Security CLI')
    .option('--json', 'Output structured JSON for AI and automation');

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
    .description('Sentinel Git Hook Entrypoint (Warn-only)')
    .action((eventName) => {
        if (eventName === 'pre-push') {
            try {
                const analysis = performLocalAnalysis({ isHook: true });
                if (analysis.violations.length > 0) {
                    console.log('\n🛡️  [Sentinel] Security advisory:');
                    console.log(`   ⚠️  ${analysis.violations.length} protected file(s) in this push.`);
                    analysis.violations.forEach(v => console.log(`      - ${v}`));
                    console.log('\n   🚨 Pro-tip: Run "sentinel heal --leaks" to fix this.');
                    console.log('');
                } else {
                    console.log('✅ [Sentinel] Code looks clean.');
                }
            } catch (e) {}
            process.exit(0); // Advisory mode never blocks
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
    .action(async (options) => {
        const db = require('../backend/lib/db');
        const gh = require('../backend/lib/gh_bridge');
        const repos = db.getRepositories().filter(r => r.local_path);
        if (repos.length === 0) process.exit(1);

        const repo = repos[0];
        if (options.auto) {
            const result = gh.pushSandboxConfig(repo.local_path);
            if (result.success) {
                db.setSandboxConsent(repo.id, true);
                console.log('✅ Sandbox pushed!');
            }
        } else {
            const template = gh.getSandboxTemplateContent();
            fs.writeFileSync('sentinel-sandbox.yml', template);
            console.log('✅ Template saved to sentinel-sandbox.yml');
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
                db.installPack(repo.id, packData, true);
                console.log('✅ Pack loaded.');
            }
        }
    });

// ─── sentinel analyze ───
program
    .command('analyze')
    .option('--local', 'Scan local diff')
    .action(() => {
        const analysis = performLocalAnalysis();
        if (analysis.violations.length > 0) {
            console.log('⚠️ Protected files detected!');
            analysis.violations.forEach(v => console.log(`   - ${v}`));
        }
        if (analysis.alerts.length > 0) {
            console.log(`🚨 Found ${analysis.alerts.length} threats!`);
        } else {
            console.log('✅ Clean.');
        }
    });

// ─── sentinel heal ───
program
    .command('heal')
    .option('--leaks', 'Unstage protected files')
    .action((options) => {
        const { execFileSync } = require('child_process');
        const analysis = performLocalAnalysis({ isHook: true });
        const cwd = process.cwd();

        if (options.leaks) {
            if (analysis.violations.length === 0) {
                console.log('✅ No leaks found.');
                return;
            }
            
            const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf-8' });
            const stagedFiles = new Set(statusOutput.split('\n').filter(l => l[0] !== ' ' && l[0] !== '?').map(l => normalizePath(l.substring(3).trim())));

            let stagedLeaks = [];
            let committedLeaks = [];

            analysis.violations.forEach(v => {
                if (stagedFiles.has(normalizePath(v))) stagedLeaks.push(v);
                else committedLeaks.push(v);
            });

            stagedLeaks.forEach(v => {
                execFileSync('git', ['reset', 'HEAD', v], { cwd });
                console.log(`   Unstaged (staged): ${v}`);
            });

            if (committedLeaks.length > 0) {
                execFileSync('git', ['reset', 'HEAD~1', '--soft'], { cwd });
                console.log('   ↩️  Undid last commit (soft).');
                committedLeaks.forEach(v => {
                    execFileSync('git', ['reset', 'HEAD', v], { cwd });
                    console.log(`   Unstaged (committed): ${v}`);
                });
                const remaining = execFileSync('git', ['diff', '--cached', '--name-only'], { cwd, encoding: 'utf-8' }).trim();
                if (remaining) {
                    execFileSync('git', ['commit', '-m', 'chore: healed by sentinel'], { cwd });
                    console.log('   ✏️  Re-committed safe files.');
                }
            }
            console.log('✅ Healing complete.');
        }
    });

// ─── sentinel protected ───
program
    .command('protected')
    .argument('[action]', 'list|add', 'list')
    .argument('[target]', 'path')
    .action((action, target) => {
        const db = require('../backend/lib/db');
        const repo = db.getRepositories().find(r => r.local_path && normalizeAbsPath(r.local_path) === normalizeAbsPath(process.cwd()));
        if (!repo) return;

        if (action === 'add' && target) {
            const rel = path.relative(repo.local_path, path.resolve(target)).replace(/\\/g, '/');
            db.addProtectedFile(repo.id, rel);
            console.log(`✅ ${rel} is now protected.`);
        } else {
            const files = db.getProtectedFiles(repo.id);
            files.forEach(f => console.log(`- ${f.file_path}`));
        }
    });

// ─── sentinel status ───
program
    .command('status')
    .action(() => {
        const db = require('../backend/lib/db');
        db.getRepositories().forEach(r => console.log(`${r.status === 'SAFE' ? '🟢' : '🔴'} ${r.github_full_name}`));
    });

// ─── sentinel link ───
program
    .command('link <path> <repo>')
    .action((p, r) => {
        const db = require('../backend/lib/db');
        db.linkRepository(path.resolve(p), r);
        console.log('✅ Linked.');
    });

// ─── sentinel list ───
program
    .command('list')
    .action(() => {
        require('../backend/lib/db').getRepositories().forEach(r => console.log(`- ${r.github_full_name}`));
    });

// ─── sentinel scan ───
program
    .command('scan')
    .action(() => {
        const db = require('../backend/lib/db');
        db.getRepositories().forEach(r => performManualScan(r.id, r.github_full_name));
    });

function run(args = process.argv) {
    program.parse(args);
}

module.exports = { run };

if (require.main === module) {
    run();
}
