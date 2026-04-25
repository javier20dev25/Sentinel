/**
 * Sentinel: Phase 1 Validator (v1.0)
 * 
 * Validates the SAFE + FORENSIC architecture on real repositories.
 * Focused on verifying False Positive Rate (FPR) and Forensic Attribution quality.
 */

'use strict';

const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

const REPOS = [
    'c:\\Users\\sleyt\\sentinel-local',
    'c:\\Users\\sleyt\\Sentinel'
];

async function runValidation() {
    console.log(`\x1b[34m[PHASE 1] Starting SAFE + FORENSIC Validation Sweep\x1b[0m`);
    console.log(`Targeting ${REPOS.length} repositories...\n`);

    const finalReport = [];

    for (const repoPath of REPOS) {
        if (!fs.existsSync(repoPath)) {
            console.warn(`[SKIP] Repository not found: ${repoPath}`);
            continue;
        }

        console.log(`\x1b[36m[AUDIT] Scanning: ${path.basename(repoPath)}\x1b[0m`);
        
        try {
            // Options: SAFE (Static only), FORENSICS: true (Git attribution)
            const results = await scanner.scanDirectory(repoPath, null, 2, { 
                profile: 'DEFAULT', 
                forensics: true 
            });

            const enrichedAlerts = results.rawAlerts.filter(a => a.forensics);
            
            console.log(`  - Files: ${results.filesScanned}`);
            console.log(`  - Total Alerts: ${results.rawAlerts.length}`);
            console.log(`  - Forensic Attribution: ${enrichedAlerts.length} alerts traced to Git history.`);
            
            const repoData = {
                name: path.basename(repoPath),
                files: results.filesScanned,
                threats: results.rawAlerts.length,
                riskScore: results.riskScore,
                attributionRate: enrichedAlerts.length > 0 ? (enrichedAlerts.length / results.rawAlerts.length * 100).toFixed(1) : 0,
                topContributors: getTopContributors(enrichedAlerts)
            };

            finalReport.push(repoData);

            // Display a sample forensic finding if available
            if (enrichedAlerts.length > 0) {
                const sample = enrichedAlerts[0];
                console.log(`  \x1b[2m[Sample] ${sample._file}:${sample.line_number} -> ${sample.forensics.author} (${sample.forensics.hash.slice(0,7)})\x1b[0m`);
            }

        } catch (e) {
            console.error(`  [ERROR] Scan failed for ${repoPath}: ${e.message}`);
        }
        console.log("");
    }

    // Save final audit log
    const logPath = path.join(__dirname, '../src/ui/backend/lab/phase1_validation_log.json');
    fs.writeFileSync(logPath, JSON.stringify(finalReport, null, 2));
    
    console.log(`\x1b[32m[PHASE 1] Validation Sweep Completed.\x1b[0m`);
    console.log(`Summary report saved to: ${logPath}`);
}

function getTopContributors(alerts) {
    const counts = {};
    alerts.forEach(a => {
        const author = a.forensics.author;
        counts[author] = (counts[author] || 0) + 1;
    });
    return Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 3);
}

runValidation();
