const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');

async function testForensics() {
    console.log("Starting AppSec Pro Forensics Test...");
    const repoPath = path.resolve(__dirname, '..');
    
    // We'll scan a file we know has some 'require' or similar that might trigger rules
    // and we'll enable 'forensics' option.
    const results = await scanner.scanDirectory(repoPath, null, 1, { profile: 'STRICT', forensics: true });
    
    console.log(`Scan completed. Files: ${results.filesScanned}, Alerts: ${results.rawAlerts.length}`);
    
    const forensicAlerts = results.rawAlerts.filter(a => a.forensics);
    console.log(`Alerts with Forensic Data: ${forensicAlerts.length}`);
    
    if (forensicAlerts.length > 0) {
        const first = forensicAlerts[0];
        console.log(`\n[FORENSIC EVIDENCE]`);
        console.log(`File: ${first._file} (Line ${first.line_number})`);
        console.log(`Author: ${first.forensics.author}`);
        console.log(`Commit: ${first.forensics.hash}`);
        console.log(`Message: ${first.forensics.summary}`);
    } else {
        console.log("No forensic data found. (Are there any alerts in the scan?)");
    }
}

testForensics();
