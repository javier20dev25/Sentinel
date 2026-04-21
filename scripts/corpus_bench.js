/**
 * Sentinel 3.5: Clean Corpus Precision Bench
 * 
 * Scans verified clean code in the workspace to measure False Positive Rate (FPR).
 * Goal: 0% FP at 80+ threshold, <5% FP at 60+ threshold.
 */

const fs = require('fs');
const path = require('path');
const { scanFile } = require('../src/ui/backend/scanner/index');

const CORPUS_DIR = path.join(__dirname, '../src/ui/backend/lib');

console.log("=== SENTINEL CORPUS PRECISION BENCH v3.5 ===");
console.log(`Target Directory: ${CORPUS_DIR}`);
console.log("-".repeat(40));

if (!fs.existsSync(CORPUS_DIR)) {
    console.error(`Error: Corpus directory ${CORPUS_DIR} not found.`);
    process.exit(1);
}

const files = fs.readdirSync(CORPUS_DIR).filter(f => f.endsWith('.js'));
let totalScore = 0;
let fp60 = 0;
let fp80 = 0;

files.forEach(file => {
    const filePath = path.join(CORPUS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf8');
    
    const results = scanFile(file, content);
    
    const maxAlert = results.alerts.reduce((max, a) => (a.riskLevel || 0) > (max.riskLevel || 0) ? a : max, { riskLevel: 0 });
    const maxScore = maxAlert.riskLevel || 0;
    totalScore += maxScore;

    if (maxScore >= 80) fp80++;
    if (maxScore >= 60) fp60++;

    console.log(`[CLEAN] ${file.padEnd(20)} | Score: ${maxScore.toString().padStart(3)}/100 | Rule: ${maxAlert.ruleName || 'None'}`);
    if (maxScore >= 60) {
        console.log(`   └─ Alert: ${maxAlert.ruleName} [${maxAlert.category}]`);
    }
});

const avgScore = totalScore / files.length;
const fp60Rate = (fp60 / files.length) * 100;
const fp80Rate = (fp80 / files.length) * 100;

console.log("\n=== CORPUS METRICS REPORT ===");
console.log(`Average Baseline Score: ${avgScore.toFixed(2)}`);
console.log(`FP Rate (60+): ${fp60Rate.toFixed(1)}%`);
console.log(`FP Rate (80+): ${fp80Rate.toFixed(1)}%`);

if (fp80 === 0 && fp60Rate < 10) {
    console.log("\n✅ STATUS: PRECISION PASS (Low Noise Profile)");
} else {
    console.log("\n❌ STATUS: PRECISION FAIL (Engine is too paranoid, calibration required)");
    process.exit(1);
}
