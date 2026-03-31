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
    
    repos.forEach(repo => {
        try {
            const prs = gh.listPRs(repo.github_full_name);
            let foundNewThreat = false;

            prs.forEach(pr => {
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
            });

            if (!foundNewThreat) {
                db.updateRepoStatus(repo.id, 'SAFE');
            }
        } catch (e) {
            console.error(`[CRITICAL] Polling error for ${repo.github_full_name}:`, e.message);
        }
    });
}

// Start polling
console.log("🚀 Sentinel Background Service Started (Polling every 1 hour)...");
checkAllRepos();
setInterval(checkAllRepos, POLLING_INTERVAL);
