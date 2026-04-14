/**
 * Sentinel: GitHub Webhooks Receiver
 * Efficiently handles GitHub events instead of aggressive polling.
 */

const crypto = require('crypto');
const db = require('./db');
const orchestrator = require('./orchestrator');
const gh = require('./gh_bridge');
const { scanFile } = require('../../scanner/index');

class WebhookHandler {

    constructor() {
        this.secret = process.env.GITHUB_WEBHOOK_SECRET || '';
    }

    /**
     * Verifies the GitHub signature.
     */
    verifySignature(req) {
        if (!this.secret) return true; // Accept if no secret is configured (dev mode)

        const signature = req.headers['x-hub-signature-256'];
        if (!signature) return false;

        const hmac = crypto.createHmac('sha256', this.secret);
        const digest = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');
        
        try {
            return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
        } catch(e) {
            return false;
        }
    }

    /**
     * Ingests and processes a webhook event.
     */
    async handleEvent(req) {
        const event = req.headers['x-github-event'];
        const payload = req.body;

        if (!payload || !payload.repository) return;

        const repoFullName = payload.repository.full_name;
        // Check if we track this repo
        const repo = db.getRepositoryByFullName(repoFullName);
        if (!repo) return;

        console.log(`[WEBHOOK] Received ${event} for ${repoFullName}`);

        try {
            switch(event) {
                case 'pull_request':
                    if (['opened', 'synchronize'].includes(payload.action)) {
                        await this.processPR(repo, payload.pull_request);
                    }
                    break;
                case 'push':
                    await this.processPush(repo, payload);
                    break;
            }
        } catch (e) {
            console.error(`[WEBHOOK ERROR] ${e.message}`);
        }
    }

    async processPR(repo, prPayload) {
        console.log(`[WEBHOOK] Processing PR #${prPayload.number}`);
        const diff = gh.getPRDiff(repo.github_full_name, prPayload.number);
        if (!diff) return;

        const scan = scanFile(`PR #${prPayload.number}.diff`, diff);
        if (scan.alerts.length > 0) {
            const category = scan.alerts.some(a => a.ruleName.includes('Secret')) ? 'SECRETS' : 'MALWARE';
            db.addScanLog(repo.id, 'WEBHOOK_PR_SCAN', 8, `Threat in PR #${prPayload.number}: ${scan.alerts[0].ruleName}`, scan.alerts, 'STATIC', category);
            db.updateRepoStatus(repo.id, 'INFECTED');
        } else {
             // Make sure we don't accidentally mark a repo SAFE if other features are infected,
             // but for now, we leave as is or update last_scan
             db.updateRepoStatus(repo.id, repo.status); // Updates timestamp only
        }
    }

    async processPush(repo, pushPayload) {
        console.log(`[WEBHOOK] Processing Push to ${pushPayload.ref}`);
        // Can be expanded to scan the pushed commit using git hooks logic
    }
}

module.exports = new WebhookHandler();
