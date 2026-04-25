const forensic = require('../src/ui/backend/scanner/forensics');
const path = require('path');

async function testSurgicalForensics() {
    console.log("Starting Surgical AppSec Pro Forensics Test...");
    const repoPath = path.resolve(__dirname, '..');
    
    // Test Git Blame on SupplyChainShield.js line 10 (should be 'use strict' or similar)
    const filePath = 'src/ui/backend/scanner/supply_chain_shield.js';
    const result = forensic.blame(repoPath, filePath, 10);
    
    console.log("\n[FORENSIC EVIDENCE - BLAME]");
    console.log(JSON.stringify(result, null, 2));

    // Test Pattern Tracing (look for 'calcRiskScore')
    console.log("\n[PATTERN TRACING - 'calcRiskScore']");
    const trace = forensic.tracePattern(repoPath, filePath, 'calcRiskScore');
    console.log(`Found ${trace.length} matching commits in history.`);
    if (trace.length > 0) {
        console.log("Latest commit:", trace[0].summary);
    }
}

testSurgicalForensics();
