/**
 * Sentinel: AppSec Pro Lab Orchestrator (v1.0)
 * 
 * Orchestrates a multi-repository audit sweep to validate detection, 
 * performance and forensic layers across diverse targets.
 */

'use strict';

const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');
const os = require('os');

const TARGETS = [
    { name: 'OWASP Juice Shop (Vulnerable App)', path: 'c:\\Users\\sleyt\\sentinel-lab\\juice-shop', depth: 2 },
    { name: 'NPM: axios (Popular Library)', path: 'c:\\Users\\sleyt\\sentinel-lab\\npm-samples\\axios_source', depth: 2 },
    { name: 'NPM: chalk (Popular Library)', path: 'c:\\Users\\sleyt\\sentinel-lab\\npm-samples\\chalk_source', depth: 2 },
    { name: 'Apache Fineract (Banking Sim)', path: 'c:\\Users\\sleyt\\sentinel-lab\\fineract', depth: 2 }
];

async function runLabSweep() {
    console.log(`\x1b[34m[LAB] Starting AppSec Pro Security Sweep\x1b[0m`);
    console.log(`Monitoring: Time, Consumption, and Attribution Layers\n`);

    let reportMd = `# Sentinel AppSec Pro Lab Report\n\n`;
    reportMd += `| Target | Files | Alerts | Risk Score | Time (ms) | Involved Layers |\n`;
    reportMd += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;

    for (const target of TARGETS) {
        if (!fs.existsSync(target.path)) {
            console.warn(`[SKIP] Target not found: ${target.name}`);
            continue;
        }

        console.log(`\x1b[36m[SWEEP] Auditing: ${target.name}...\x1b[0m`);
        
        const start = Date.now();
        const startMem = process.memoryUsage().heapUsed;

        try {
            const results = await scanner.scanDirectory(target.path, null, target.depth, { 
                profile: 'DEFAULT', 
                forensics: true 
            });

            const duration = Date.now() - start;
            const memUsed = Math.round((process.memoryUsage().heapUsed - startMem) / 1024 / 1024);
            
            console.log(`  - Files: ${results.filesScanned}`);
            console.log(`  - Alerts: ${results.rawAlerts.length}`);
            console.log(`  - Duration: ${duration}ms`);
            console.log(`  - Memory Delta: ${memUsed}MB`);

            const layers = ['Static'];
            if (results.rawAlerts.some(a => a.forensics)) layers.push('Forensic');
            if (target.name.includes('NPM')) layers.push('Sandbox-Ready');

            const score = results.riskScore !== undefined ? results.riskScore : 0;
            reportMd += `| ${target.name} | ${results.filesScanned} | ${results.rawAlerts.length} | ${score.toFixed(2)} | ${duration}ms | ${layers.join(', ')} |\n`;

        } catch (e) {
            console.error(`  [ERROR] Audit failed: ${e.message}`);
        }
        console.log("");
    }

    const reportPath = path.join(__dirname, '../docs/LAB_SWEEP_REPORT.md');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, reportMd);

    console.log(`\x1b[32m[LAB] Sweep Completed. Report saved to: ${reportPath}\x1b[0m`);
}

runLabSweep();
