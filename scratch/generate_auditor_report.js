/**
 * Sentinel: Auditor Detail Extractor (v1.0)
 * 
 * Extracts exact reasons and code snippets for a specific author.
 * Used to explain 'Malicious' labeling in forensic reports.
 */

'use strict';

const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

async function generateAuditorReport() {
    const authors = ['javier20dev25', 'Javier Astaroth'];
    console.log(`\x1b[34m[AUDITOR] Generating detailed report for authors: ${authors.join(', ')}\x1b[0m`);
    
    const repoPath = 'c:\\Users\\sleyt\\sentinel-local';
    const results = await scanner.scanDirectory(repoPath, null, 2, { profile: 'DEFAULT', forensics: true });
    
    const authorAlerts = results.rawAlerts.filter(a => a.forensics && authors.includes(a.forensics.author));
    
    let reportMd = `# Sentinel Forensic Audit Report\n\n`;
    reportMd += `**Target Authors:** ${authors.join(', ')}\n`;
    reportMd += `**Scan Date:** ${new Date().toISOString()}\n`;
    reportMd += `**Total Alerts Attributed:** ${authorAlerts.length}\n\n`;
    reportMd += `| File | Line | Rule ID | Description | Commit |\n`;
    reportMd += `| :--- | :--- | :--- | :--- | :--- |\n`;

    authorAlerts.slice(0, 50).forEach(a => {
        reportMd += `| ${a._file} | ${a.line_number} | \`${a.type}\` | ${a.description} | \`${a.forensics.hash.slice(0,7)}\` |\n`;
    });

    const reportPath = path.join(__dirname, '../docs/INTERNAL_AUDIT_REPORT.md');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, reportMd);

    console.log(`\x1b[32m[SUCCESS] Auditor Report generated at: ${reportPath}\x1b[0m`);
    
    authors.forEach(author => {
        const triggers = authorAlerts.filter(a => a.forensics.author === author);
        console.log(`First 5 triggers for ${author}:`);
        triggers.slice(0, 5).forEach(a => {
            console.log(`  - [${a.type}] in ${a._file}:${a.line_number} (${a.description})`);
        });
    });
}

generateAuditorReport();
