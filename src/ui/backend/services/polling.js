/**
 * Sentinel: Background Polling Service
 */

const db = require('../lib/db');
const gh = require('../lib/gh_bridge');
const { scanFile } = require('../scanner/index');
const notifier = require('node-notifier');

const POLLING_INTERVAL = 60 * 60 * 1000; // 1 hour

function checkAllRepos() {
    console.log(`[${new Date().toISOString()}] Starting background scan...`);
    const repos = db.getRepositories();
    
    // Use a sequential loop with small delays to prevent CPU/Memory spikes
    (async () => {
        for (const repo of repos) {
            try {
                const prs = gh.listPRs(repo.github_full_name);
                let foundNewThreat = false;

                for (const pr of prs) {
                    const diff = gh.getPRDiff(repo.github_full_name, pr.number);
                    if (diff) {
                        const results = scanFile(`PR #${pr.number}.diff`, diff);
                        if (results.alerts.length > 0) {
                            foundNewThreat = true;
                            db.addScanLog(repo.id, 'BACKGROUND_SCAN', 10, `Background alert for PR #${pr.number}`, results.alerts);
                            db.updateRepoStatus(repo.id, 'INFECTED');

                            notifier.notify({
                                title: '🕵️ Sentinel: Background Alert',
                                message: `Suspicious activity detected in ${repo.github_full_name} (PR #${pr.number})`,
                                sound: true
                            });
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

// Start polling - DEFERRED to avoid blocking main process startup
console.log("🚀 Sentinel Background Service Initializing...");
setTimeout(() => {
    console.log("⚡ Starting first background scan...");
    checkAllRepos();
    setInterval(checkAllRepos, POLLING_INTERVAL);
}, 5000); // 5 second delay to let server start and UI load
