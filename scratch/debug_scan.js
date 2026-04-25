const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');

async function debugScan() {
    const repoPath = 'c:\\Users\\sleyt\\sentinel-local';
    // Let's scan specifically src/ui/backend/scanner/supply_chain_shield.js
    // We know it has 'require' which triggers rules
    const results = await scanner.scanDirectory(repoPath, null, 2, { profile: 'DEFAULT', forensics: true });
    
    console.log("Total Alerts:", results.rawAlerts.length);
    if (results.rawAlerts.length > 0) {
        console.log("First Alert:", results.rawAlerts[0].type, "in", results.rawAlerts[0]._file);
        console.log("Forensics for first alert:", results.rawAlerts[0].forensics);
    }
}

debugScan();
