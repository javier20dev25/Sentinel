/**
 * Sentinel: Massive Systematic Benchmark (v2.0)
 * 
 * The "Firing Range": Runs multi-profile regression testing across
 * Benign, Vulnerable, Supply Chain, and Fintech categories.
 */

'use strict';

const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

const LAB_DIR = 'c:\\Users\\sleyt\\sentinel-lab';

const CATEGORIES = {
    BENIGN: [
        { name: 'Webpack', path: path.join(LAB_DIR, 'webpack') },
        { name: 'Babel', path: path.join(LAB_DIR, 'babel') },
        { name: 'Vite', path: path.join(LAB_DIR, 'vite') },
        { name: 'ESLint', path: path.join(LAB_DIR, 'eslint') },
        { name: 'Next.js', path: path.join(LAB_DIR, 'nextjs') }
    ],
    VULNERABLE: [
        { name: 'Juice Shop', path: path.join(LAB_DIR, 'juice-shop') },
        { name: 'WebGoat', path: path.join(LAB_DIR, 'WebGoat') },
        { name: 'DVWA', path: path.join(LAB_DIR, 'DVWA') }
    ],
    FINTECH: [
        { name: 'Fineract', path: path.join(LAB_DIR, 'fineract') },
        { name: 'Mifos', path: path.join(LAB_DIR, 'mifos') }
    ],
    SUPPLY_CHAIN: [
        { name: 'Axios', path: path.join(LAB_DIR, 'npm-samples/axios_source') },
        { name: 'Chalk', path: path.join(LAB_DIR, 'npm-samples/chalk_source') },
        { name: 'is-promise', path: path.join(LAB_DIR, 'npm-samples/is-promise') },
        { name: 'left-pad', path: path.join(LAB_DIR, 'npm-samples/left-pad') }
    ]
};

const PROFILES = ['strict'];
const RESULTS = [];

async function runMassiveBenchmark() {
    console.log(`\x1b[34m[BENCHMARK] Initiating The Firing Range\x1b[0m`);
    console.log(`Categories: Benign, Vulnerable, Fintech, Supply Chain\n`);

    for (const profile of PROFILES) {
        console.log(`\n\x1b[35m=== Profile: ${profile.toUpperCase()} ===\x1b[0m`);
        
        for (const [categoryName, targets] of Object.entries(CATEGORIES)) {
            console.log(`\n\x1b[33m-- Category: ${categoryName} --\x1b[0m`);
            
            for (const target of targets) {
                if (!fs.existsSync(target.path)) {
                    console.warn(`  [SKIP] Not found: ${target.name}`);
                    continue;
                }

                process.stdout.write(`  Scanning ${target.name}... `);
                
                const start = Date.now();
                const startMem = process.memoryUsage().heapUsed;

                try {
                    // Depth 1 to avoid taking hours on massive repos like Next.js or Webpack
                    // We just want a representative sample of performance.
                    const results = await scanner.scanDirectory(target.path, null, 1, { 
                        profile: profile, 
                        forensics: false 
                    });

                    const duration = Date.now() - start;
                    const memUsed = Math.max(0, Math.round((process.memoryUsage().heapUsed - startMem) / 1024 / 1024));
                    
                    const score = results.riskScore !== undefined ? results.riskScore : 0;
                    const alerts = results.rawAlerts.length;
                    const enriched = results.rawAlerts.filter(a => a.forensics).length;
                    
                    // Simple FPR/FNR estimation for demonstration
                    // Benign -> Alerts = False Positives
                    // Vulnerable -> Clean = False Negatives
                    let fpr = categoryName === 'BENIGN' ? (alerts > 0 ? (alerts / results.filesScanned * 100).toFixed(1) : 0) : 'N/A';
                    let fnr = categoryName === 'VULNERABLE' ? (alerts === 0 ? 100 : 0) : 'N/A';

                    console.log(`Done (${duration}ms)`);
                    
                    RESULTS.push({
                        profile,
                        category: categoryName,
                        target: target.name,
                        files: results.filesScanned,
                        alerts,
                        score: score.toFixed(2),
                        fpr: fpr !== 'N/A' ? `${fpr}%` : '-',
                        fnr: fnr !== 'N/A' ? `${fnr}%` : '-',
                        timeMs: duration,
                        memMb: memUsed,
                        enriched
                    });

                } catch (e) {
                    console.log(`\x1b[31mError: ${e.message}\x1b[0m`);
                }
            }
        }
    }

    generateReport();
}

function generateReport() {
    const reportPath = path.join(__dirname, '../docs/MASSIVE_BENCHMARK.md');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    
    let md = `# Sentinel Massive Systematic Benchmark\n\n`;
    
    for (const profile of PROFILES) {
        md += `## Profile: ${profile.toUpperCase()}\n\n`;
        md += `| Category | Target | Files | Alerts | Score | FPR | FNR | Time(ms) | Mem(MB) | Forensics |\n`;
        md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
        
        const profileResults = RESULTS.filter(r => r.profile === profile);
        for (const r of profileResults) {
            md += `| ${r.category} | ${r.target} | ${r.files} | ${r.alerts} | ${r.score} | ${r.fpr} | ${r.fnr} | ${r.timeMs} | ${r.memMb} | ${r.enriched} |\n`;
        }
        md += `\n`;
    }

    fs.writeFileSync(reportPath, md);
    console.log(`\n\x1b[32m[SUCCESS] Benchmark Report saved to: ${reportPath}\x1b[0m`);
}

runMassiveBenchmark();
