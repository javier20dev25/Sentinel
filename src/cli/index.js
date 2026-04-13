#!/usr/bin/env node

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

// ─── Command: Sandbox (Sentinel 3.0) ────────────────────────────────────────

const sandbox = program
    .command('sandbox')
    .description('Manage and monitor dynamic sandbox analysis in GitHub Actions');

sandbox
    .command('generate')
    .description('Generate the sentinel-sandbox.yml workflow template')
    .action(() => {
        const ci = require('../ui/backend/lib/ci_sandbox');
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
        const ci = require('../ui/backend/lib/ci_sandbox');
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
            console.log("Exiting (async mode). Use 'sntl sandbox status' to check progress.");
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
        const ci = require('../ui/backend/lib/ci_sandbox');
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
    const ci = require('../ui/backend/lib/ci_sandbox');
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
    }

    ci.cleanupTempDir(download.tempDir);
}

program.parse(process.argv);
