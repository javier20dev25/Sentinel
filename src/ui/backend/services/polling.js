/**
 * Sentinel: Background Polling Service (RESILIENT)
 * 
 * RESILIENCE: node-notifier is loaded lazily and wrapped in try/catch
 * because its vendored binaries (snoreToast.exe) may not be accessible
 * when running from inside an ASAR package.
 */

const db = require('../lib/db');
const gh = require('../lib/gh_bridge');
const { scanFile, analyzeLifecycleScripts } = require('../scanner/index');

// Lazy-load node-notifier to prevent crash if binaries are inaccessible
let notifier = null;
try {
    notifier = require('node-notifier');
} catch (e) {
    console.warn('[POLLING] node-notifier unavailable (packaged mode), desktop notifications disabled:', e.message);
}

function safeNotify(options) {
    try {
        if (notifier) notifier.notify(options);
    } catch (e) {
        console.warn('[POLLING] Notification failed:', e.message);
    }
}

const POLLING_INTERVAL = 60 * 60 * 1000; // 1 hour

let pollingInterval = null;
let lastRunTime = null;
let isPollingActive = false;

function checkAllRepos() {
    isPollingActive = true;
    lastRunTime = Date.now();
    console.log(`[${new Date().toISOString()}] Starting background scan...`);
    const repos = db.getRepositories();
    
    // Use a sequential loop with small delays to prevent CPU/Memory spikes
    (async () => {
        for (const repo of repos) {
            try {
                const prs = gh.listPRs(repo.github_full_name);
                let foundNewThreat = false;

                for (const pr of prs) {
                    // Phase 2: Advanced Supply Chain Analysis
                    const analysis = await gh.analyzePRContent(repo.github_full_name, pr.number, pr.author?.login || pr.author);
                    
                    if (analysis.hasSensitiveChanges) {
                        console.log(`[SUPPLY-CHAIN] Sensitive changes in PR #${pr.number} by ${pr.author?.login || pr.author}`);
                        const pkgContent = gh.getRemoteFileContent(repo.github_full_name, 'package.json');
                        
                        if (pkgContent) {
                            const results = scanFile('package.json', pkgContent);
                            // Attach author metadata for deeper scoring
                            const supplyChainAlerts = analyzeLifecycleScripts(pkgContent, analysis.authorReputation);
                            
                            if (supplyChainAlerts.length > 0) {
                                foundNewThreat = true;
                                db.addScanLog(repo.id, 'SUPPLY_CHAIN_ALERT', 9, `Supply chain threat in PR #${pr.number} (${analysis.authorReputation.username})`, supplyChainAlerts);
                                db.updateRepoStatus(repo.id, 'INFECTED');

                                safeNotify({
                                    title: '🚨 Sentinel: Supply Chain Alert',
                                    message: `Malicious script in ${repo.github_full_name} PR #${pr.number} by @${analysis.authorReputation.username}`,
                                    sound: true
                                });
                            }
                        }
                    } else if (analysis.diff) {
                        // Standard diff scan for non-package.json files
                        const results = scanFile(`PR #${pr.number}.diff`, analysis.diff);
                        if (results.alerts.length > 0) {
                            foundNewThreat = true;
                            db.addScanLog(repo.id, 'BACKGROUND_SCAN', 10, `Background alert for PR #${pr.number}`, results.alerts);
                            db.updateRepoStatus(repo.id, 'INFECTED');
                        }
                    }
                    // Small breathing room between PRs
                    await new Promise(r => setTimeout(r, 500));
                }

                if (!foundNewThreat) {
                    db.updateRepoStatus(repo.id, 'SAFE');
                }
            } catch (e) {
                console.error(`[CRITICAL] Polling error for ${repo.github_full_name}:`, e.message);
            }
            // Breathing room between Repos
            await new Promise(r => setTimeout(r, 2000));
        }
    })();
}

function start() {
    if (pollingInterval) return;
    console.log("🚀 Sentinel Background Service Starting...");
    checkAllRepos();
    pollingInterval = setInterval(checkAllRepos, POLLING_INTERVAL);
    isPollingActive = true;
}

function stop() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
    isPollingActive = false;
    console.log("🛑 Sentinel Background Service Stopped.");
}

function isActive() {
    return isPollingActive;
}

function getLastRun() {
    return lastRunTime;
}

// Start polling - DEFERRED to avoid blocking main process startup
setTimeout(() => {
    start();
}, 5000); // 5 second delay to let server start and UI load

module.exports = {
    start,
    stop,
    isActive,
    getLastRun
};
