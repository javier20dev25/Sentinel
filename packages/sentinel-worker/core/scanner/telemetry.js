/**
 * Sentinel Core: Telemetry Reporter
 * 
 * Securely transmits anonymized scan results to the Intelligence Bridge API.
 * Designed to NEVER break the local scan if the network fails.
 */

'use strict';

const https = require('https');
const crypto = require('crypto');
const PolicyEngine = require('./policy_engine');

const INGEST_API_URL = process.env.SENTINEL_API_URL || 'https://api.sentinel-appsec.com/api/v1/intelligence/ingest';

/**
 * Main reporting entrypoint.
 * @param {Object} scanResults - The output from auditWithSurgicalSandbox
 * @param {string} targetPath - Local path (used ONLY for hashing, never sent)
 */
async function reportIntelligence(scanResults, targetPath) {
    // 1. Check Opt-In Policy
    const policy = PolicyEngine.activePolicy;
    if (policy.governance.intelligence_opt_in !== true) {
        // Telemetry is disabled by default. Do nothing.
        return;
    }

    // Only report if there's actually a threat detected (reduces noise/costs)
    if (scanResults.riskScore < 0.40) {
        return;
    }

    // 2. Build Safe Payload
    const repoHash = crypto.createHash('sha256').update(targetPath).digest('hex');
    const tier = policy.governance.data_sharing_level === 2 ? 'PRO' : 'FREE';

    // Extract the worst threat pattern (simplified for the pipeline)
    const worstAlert = scanResults.rawAlerts && scanResults.rawAlerts.length > 0 
        ? scanResults.rawAlerts[0] 
        : { category: 'unknown', pattern: 'unclassified_risk' };

    const payload = {
        meta: {
            timestamp: new Date().toISOString(),
            cli_version: "3.0.0", // Hardcoded for V3 architecture
            repo_hash: repoHash,
            language: "javascript",
            tier: tier
        },
        threat: {
            category: worstAlert.category || 'heuristic_anomaly',
            pattern: worstAlert.pattern || 'suspicious_code_block',
            risk_score: scanResults.riskScore,
            confidence: 0.85 // Default confidence for now
        },
        metrics: {
            scan_time_ms: scanResults.performance ? scanResults.performance.durationMs : 0,
            files_scanned: scanResults.filesScanned || 0
        }
    };

    // Include AST features if PRO tier
    if (tier === 'PRO') {
        payload.ast_features = {
            uses_eval: true, // Mocked for integration
            dynamic_require: false,
            entropy: 5.5
        };
    }

    // 3. Send via strict non-blocking network request
    await sendToAPI(payload);
}

/**
 * Fires the HTTP request with a strict 3000ms timeout.
 * Catches all errors so the CLI exit(0/1) logic is never interrupted.
 */
function sendToAPI(payload) {
    return new Promise((resolve) => {
        try {
            const data = JSON.stringify(payload);
            const token = process.env.SENTINEL_JWT || 'mock-valid-jwt'; // Local auth token

            const url = new URL(INGEST_API_URL);
            const options = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname,
                method: 'POST',
                timeout: 3000, // STRICT 3-second timeout
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': data.length,
                    'Authorization': `Bearer ${token}`
                }
            };

            const req = https.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    // We don't block on success. Just resolve.
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        try {
                            const parsed = JSON.parse(responseData);
                            // Store the returned UUID in memory if needed for logs
                            if (parsed.event_id) {
                                process.env.LAST_SENTINEL_EVENT_ID = parsed.event_id;
                            }
                        } catch (e) {}
                    }
                    resolve();
                });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve(); // Fail silently
            });

            req.on('error', (e) => {
                // Fail silently. Network errors must not crash the local scan.
                resolve();
            });

            req.write(data);
            req.end();

        } catch (error) {
            // Absolute fallback. 
            resolve();
        }
    });
}

module.exports = { reportIntelligence };
