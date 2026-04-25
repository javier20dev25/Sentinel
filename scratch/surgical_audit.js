const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

async function surgicalAudit() {
    const authors = ['javier20dev25', 'Javier Astaroth'];
    const repoPath = 'c:\\Users\\sleyt\\sentinel-local';
    
    // Scan only the scanner directory to be fast
    const targetPath = path.join(repoPath, 'src/ui/backend/scanner');
    const results = await scanner.scanDirectory(targetPath, null, 1, { profile: 'DEFAULT', forensics: true });
    
    const authorAlerts = results.rawAlerts.filter(a => a.forensics && authors.includes(a.forensics.author));
    
    console.log(`Audited ${results.filesScanned} files. Found ${authorAlerts.length} attributed alerts.`);
    
    let reportMd = `# Sentinel Forensic Audit Report (Surgical)\n\n`;
    reportMd += `**Authors:** ${authors.join(', ')}\n\n`;
    reportMd += `| File | Line | Rule | Reason | Commit |\n`;
    reportMd += `| :--- | :--- | :--- | :--- | :--- |\n`;

    authorAlerts.forEach(a => {
        reportMd += `| ${a._file} | ${a.line_number} | \`${a.type}\` | ${a.description} | \`${a.forensics.hash.slice(0,7)}\` |\n`;
    });

    fs.writeFileSync('docs/SURGICAL_AUDIT.md', reportMd);
    console.log("Report saved to docs/SURGICAL_AUDIT.md");
    
    // Print first 3 to console
    authorAlerts.slice(0, 3).forEach(a => {
        console.log(`[ALERT] ${a._file}:${a.line_number} -> ${a.type} (${a.description})`);
    });
}

surgicalAudit();
