/**
 * Sentinel: Ground Truth Triage CLI (v1.0)
 * 
 * Allows Security Operations Center (SOC) engineers to review
 * anomalies logged by the Shadow Webhook, mark them as False Positives (dismissed),
 * and establish the ground truth necessary to calculate Precision and Recall.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const TELEMETRY_FILE = path.join(__dirname, '../../../docs/shadow_telemetry.jsonl');

async function main() {
    console.log("🛡️ Sentinel Ground Truth Triage CLI");
    console.log("=====================================\n");

    if (!fs.existsSync(TELEMETRY_FILE)) {
        console.log("✅ No anomalies found. Telemetry log is empty.");
        return;
    }

    const lines = fs.readFileSync(TELEMETRY_FILE, 'utf8').split('\n').filter(l => l.trim().length > 0);
    const updatedLines = [];
    
    let reviewedCount = 0;
    let fpCount = 0;

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const prompt = (query) => new Promise((resolve) => rl.question(query, resolve));

    for (let i = 0; i < lines.length; i++) {
        const record = JSON.parse(lines[i]);
        
        // Skip already reviewed/dismissed records
        if (record.human_label !== null || record.dismissed) {
            updatedLines.push(lines[i]);
            continue;
        }

        console.log(`\n🚨 Alert [${i + 1}/${lines.length}]`);
        console.log(`  📦 Repo:      ${record.repo} (PR #${record.pr || 'N/A'})`);
        console.log(`  📄 File:      ${record.file || 'N/A'}`);
        console.log(`  👤 Author:    ${record.author}`);
        console.log(`  ⚠️ Verdict:   ${record.verdict} (Impact: ${record.impact}, Conf: ${record.confidence})`);
        console.log(`  🧠 Rationale: ${record.rationale}`);
        
        if (record.graph && record.graph.length > 0) {
            console.log(`  🕸️  Graph:     ${record.graph.join('\n                 ')}`);
        }

        let decision = '';
        while (decision !== 'y' && decision !== 'n' && decision !== 'skip' && decision !== 'q') {
            decision = (await prompt('\n🤔 Is this a False Positive? (y/n/skip/q=quit): ')).toLowerCase();
        }

        if (decision === 'q') {
            // Keep the rest of the lines unchanged
            for (let j = i; j < lines.length; j++) {
                updatedLines.push(lines[j]);
            }
            break;
        } else if (decision === 'skip') {
            updatedLines.push(lines[i]);
            continue;
        }

        const isFalsePositive = (decision === 'y');
        if (isFalsePositive) fpCount++;
        reviewedCount++;

        record.dismissed = isFalsePositive;
        record.human_label = isFalsePositive ? 'FALSE_POSITIVE' : 'TRUE_POSITIVE';
        
        updatedLines.push(JSON.stringify(record));
        console.log(isFalsePositive ? "✅ Marked as False Positive (Dismissed)" : "🔥 Marked as True Positive (Confirmed)");
    }

    rl.close();

    // Write updated lines back to file
    fs.writeFileSync(TELEMETRY_FILE, updatedLines.join('\n') + '\n', 'utf8');

    console.log(`\n🛑 Triage session complete.`);
    console.log(`📊 Reviewed: ${reviewedCount} | FPs: ${fpCount} | TPs: ${reviewedCount - fpCount}`);
}

main().catch(console.error);
