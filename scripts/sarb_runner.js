/**
 * Sentinel 3.4: SARB Runner (Sentinel Adversarial Regression Bench)
 * 
 * Reports:
 * 1. Detection Rate (Success vs Bypass)
 * 2. Performance (ms/file) per Level
 * 3. Confidence Explainability
 */

const fs = require('fs');
const path = require('path');
const { scanFile } = require('../src/ui/backend/scanner/index');

const TEST_FILE = path.join(__dirname, '../tests/adversarial/sarb_suite.js');
const BENCH_START = Date.now();

console.log("=== SENTINEL SARB BENCHMARK v3.4 ===");
console.log(`Target: ${path.basename(TEST_FILE)}`);
console.log("-".repeat(40));

if (!fs.existsSync(TEST_FILE)) {
    console.error("Error: sarb_suite.js not found.");
    process.exit(1);
}

const content = fs.readFileSync(TEST_FILE, 'utf8');

// Dividir la suite en bloques. Cada caso empieza con un comentario /**
const cases = content.split(/\n(?=\/\*\*)/g).filter(s => s.trim().length > 0);

let detected = 0;
let total = cases.length;
let performanceData = [];

cases.forEach((caseBody, idx) => {
    const caseId = idx + 1;
    const start = process.hrtime.bigint();
    
    // Ejecutar el scanner adaptativo
    const results = scanFile(`sarb_case_${caseId}.js`, caseBody);
    
    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1_000_000;
    performanceData.push(durationMs);

    const isDetected = results.alerts.some(a => a.severity === 'CRITICAL' || a.category === 'behavior-graph');
    if (isDetected) detected++;

    console.log(`[CASE ${caseId}] ${isDetected ? '✅ DETECTED ' : '❌ BYPASSED '} (${durationMs.toFixed(2)}ms)`);
    if (!isDetected) {
        console.log("   DEBUG (Results):", JSON.stringify(results.alerts.map(a => ({cat: a.category, sev: a.severity})), null, 2));
    }
    if (isDetected) {
        const topAlert = results.alerts.find(a => a.category === 'behavior-graph' || a.isKillSwitch);
        if (topAlert) {
            console.log(`   └─ ${topAlert.ruleName}`);
            console.log(`   └─ ${topAlert.description}`);
        }
    }
    console.log("-".repeat(20));
});

const totalTime = Date.now() - BENCH_START;
const detectionRate = (detected / total) * 100;
const avgPerf = performanceData.reduce((a, b) => a + b, 0) / total;

console.log("\n=== SARB KPI REPORT ===");
console.log(`Detection Rate: ${detectionRate.toFixed(1)}% (${detected}/${total})`);
console.log(`Avg Performance: ${avgPerf.toFixed(2)}ms/file`);
console.log(`Total Runtime: ${totalTime}ms`);

if (detectionRate >= 95 && avgPerf < 50) {
    console.log("\n✅ STATUS: PASS (SARB Grade: ENTERPRISE)");
} else {
    console.log("\n❌ STATUS: FAIL (Optimization or Logic Tuning Required)");
}
