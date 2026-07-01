/**
 * Sentinel: Massive Adversarial Red Team Suite (v1.0)
 * 
 * Target: Validate Recall, False Positive Rate, Silent Failure Rate,
 *         Dampening Ratio, and Latency against a corpus of 100 cases.
 * 
 * Rules: 
 *   - Recall >= 90%
 *   - Silent Failures = 0 in strong killchains
 *   - FP <= 5% in mature benigns
 *   - P95 latency sane
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const DataContract = require('../packages/sentinel-worker/core/scanner/data_contract');
const ThreatMemory = require('../packages/sentinel-worker/core/scanner/threat_memory');

const CORPUS_DIR = path.join(__dirname, 'redteam_corpus');
const OUTPUT_DIR = path.join(__dirname, '..', 'data', 'redteam');

if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Ensure ThreatMemory is ready
ThreatMemory.getStats();

function loadCorpus() {
    const corpus = [];
    const dirs = ['benign', 'malicious', 'edge_cases'];
    
    for (const d of dirs) {
        const dirPath = path.join(CORPUS_DIR, d);
        if (!fs.existsSync(dirPath)) continue;
        const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.json'));
        
        for (const file of files) {
            const data = JSON.parse(fs.readFileSync(path.join(dirPath, file), 'utf8'));
            if (!data.expectedVerdict || !data.signals || !data.repoProfile) {
                console.error(`❌ FATAL: Invalid schema in ${file}`);
                process.exit(1);
            }
            corpus.push(data);
        }
    }
    return corpus;
}

function runScanner(testCase) {
    const startTime = Date.now();
    const findings = testCase.signals.map(s => ({ intent: s, severity: 8, file: testCase.file }));
    
    const history = JSON.parse(JSON.stringify(ThreatMemory.getRepoHistory(testCase.repo)));
    const oracleCtx = {
        isAuthorized: true,
        user: 'redteam_actor',
        mode: 'REPO',
        repoId: testCase.repo,
        historyOverride: history
    };

    const rawResult = RiskOrchestrator.arbitrate(findings, testCase.repoProfile, oracleCtx);
    const latency = Date.now() - startTime;

    const canonical = DataContract.normalize(rawResult, {
        scanId: `scan-${testCase.id}`,
        repoId: testCase.repo,
        repoProfile: testCase.repoProfile,
        file: testCase.file,
        author: oracleCtx.user
    });

    const decisionHash = DataContract.toObservationRecord(canonical, { file: testCase.file }).decision_hash;

    let isPass = false;
    let expectedSet = testCase.expectedVerdict.split('|').map(s => s.trim());
    if (expectedSet.includes(canonical.verdict)) {
        isPass = true;
    } else if (testCase.expectedVerdict === 'BLOCK' && canonical.verdict.startsWith('REVIEW_HIGH_SIGNAL')) {
        // Accept REVIEW_HIGH_SIGNAL for some BLOCK scenarios if requested, but typically we treat mismatch as false
        isPass = false;
    }

    return {
        id: testCase.id,
        category: testCase.category,
        expectedVerdict: testCase.expectedVerdict,
        actualVerdict: canonical.verdict,
        confidence: canonical.decisionConfidence,
        rawImpact: canonical.rawImpact,
        effectiveImpact: canonical.effectiveImpact,
        calibrationVersion: canonical.calibrationVersion,
        repo: testCase.repo,
        repoProfile: testCase.repoProfile,
        file: testCase.file,
        signals: testCase.signals,
        decisionHash,
        pass: isPass,
        latencyMs: latency,
        critical: testCase.critical,
        historicalState: history
    };
}

function analyzeFailures(results) {
    const failures = [];
    let typeA = 0, typeB = 0, typeC = 0, typeD = 0;

    for (const res of results) {
        if (res.pass) continue;

        let type = 'UNKNOWN';
        let severity = 'LOW';

        if (res.category === 'malicious') {
            if (res.actualVerdict === 'PASS') {
                type = 'Type A - Silent Failure';
                severity = 'CRITICAL';
                typeA++;
            } else {
                type = 'Type B - Under Escalation';
                severity = 'HIGH';
                typeB++;
            }
        } else if (res.category === 'benign') {
            if (res.actualVerdict === 'BLOCK') {
                type = 'Type C - False Positive';
                severity = 'MEDIUM';
                typeC++;
            } else if (res.actualVerdict.startsWith('REVIEW')) {
                type = 'Type D - Over Review';
                severity = 'LOW';
                typeD++;
            }
        }

        failures.push({ ...res, failureType: type, severity });
    }

    return { failures, counts: { typeA, typeB, typeC, typeD } };
}

function calculateMetrics(results) {
    let tp = 0, fn = 0, fp = 0, tn = 0;
    let totalBenign = 0, totalMalicious = 0;
    const latencies = [];
    const profiles = {};

    for (const res of results) {
        latencies.push(res.latencyMs);

        // Track Dampening per profile
        if (!profiles[res.repoProfile]) profiles[res.repoProfile] = { rawSum: 0, effSum: 0, count: 0 };
        profiles[res.repoProfile].rawSum += res.rawImpact;
        profiles[res.repoProfile].effSum += res.effectiveImpact;
        profiles[res.repoProfile].count++;

        if (res.category === 'malicious') {
            totalMalicious++;
            if (res.actualVerdict === 'BLOCK' || res.actualVerdict === 'REVIEW_HIGH_SIGNAL') tp++;
            else if (res.actualVerdict === 'PASS') fn++;
        } else if (res.category === 'benign') {
            totalBenign++;
            if (res.actualVerdict === 'BLOCK') fp++;
            else tn++;
        }
    }

    const recall = totalMalicious > 0 ? (tp / (tp + fn)) * 100 : 100;
    const fpRate = totalBenign > 0 ? (fp / totalBenign) * 100 : 0;
    
    latencies.sort((a, b) => a - b);
    const median = latencies[Math.floor(latencies.length / 2)] || 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0;

    const dampening = {};
    for (const [p, val] of Object.entries(profiles)) {
        dampening[p] = val.rawSum > 0 ? (1 - (val.effSum / val.rawSum)) * 100 : 0;
    }

    return { recall, fpRate, dampening, median, p95, totalBenign, totalMalicious };
}

function generateReport(corpus, results, metrics, failureAnalysis) {
    const total = corpus.length;
    let benignPass = 0, benignReview = 0, benignBlock = 0;
    let malBlock = 0, malReview = 0, malPass = 0;

    for (const res of results) {
        if (res.category === 'benign') {
            if (res.actualVerdict === 'PASS') benignPass++;
            else if (res.actualVerdict.startsWith('REVIEW')) benignReview++;
            else benignBlock++;
        } else if (res.category === 'malicious') {
            if (res.actualVerdict === 'BLOCK' || res.actualVerdict === 'SECURITY_HOLD') malBlock++;
            else if (res.actualVerdict.startsWith('REVIEW')) malReview++;
            else malPass++;
        }
    }

    let report = `=================================================\n`;
    report += `SENTINEL RED TEAM REPORT\n`;
    report += `=================================================\n\n`;
    report += `Total: ${total}\n\n`;
    
    report += `Benign:\n`;
    report += `PASS: ${benignPass}\n`;
    report += `REVIEW: ${benignReview}\n`;
    report += `BLOCK: ${benignBlock}\n\n`;

    report += `Malicious:\n`;
    report += `BLOCK: ${malBlock}\n`;
    report += `REVIEW_HIGH_SIGNAL: ${malReview}\n`;
    report += `PASS: ${malPass} ${malPass > 0 ? '❌' : '✅'}\n\n`;

    report += `Recall: ${metrics.recall.toFixed(1)}%\n`;
    report += `FP Rate: ${metrics.fpRate.toFixed(1)}%\n`;
    report += `Silent Failure: ${malPass} ❌\n\n`;

    report += `Dampening:\n`;
    for (const [p, ratio] of Object.entries(metrics.dampening)) {
        report += `${p}: ${ratio.toFixed(1)}%\n`;
    }

    report += `\nLatency:\n`;
    report += `Median: ${metrics.median}ms\n`;
    report += `P95: ${metrics.p95}ms\n\n`;

    if (failureAnalysis.failures.length > 0) {
        report += `FAILURES:\n`;
        for (const f of failureAnalysis.failures) {
            report += `- [${f.severity}] ${f.id} (${f.expectedVerdict} != ${f.actualVerdict}) [${f.failureType}]\n`;
        }
    }

    console.log(report);
    fs.writeFileSync(path.join(OUTPUT_DIR, 'report.md'), report);
    fs.writeFileSync(path.join(OUTPUT_DIR, 'redteam_results.json'), JSON.stringify(results, null, 2));
    fs.writeFileSync(path.join(OUTPUT_DIR, 'failures.json'), JSON.stringify(failureAnalysis.failures, null, 2));
}

// MAIN
const corpus = loadCorpus();
if (corpus.length === 0) {
    console.error("❌ Corpus is empty. Please generate it first.");
    process.exit(1);
}

const results = [];
for (const testCase of corpus) {
    results.push(runScanner(testCase));
}

const metrics = calculateMetrics(results);
const failureAnalysis = analyzeFailures(results);

generateReport(corpus, results, metrics, failureAnalysis);

let hasCritical = failureAnalysis.counts.typeA > 0;
if (hasCritical) {
    console.error("\n❌ RED TEAM FAILED: Silent Failures Detected!");
    process.exit(1);
}

if (metrics.recall < 90) {
    console.error(`\n❌ RED TEAM FAILED: Recall too low (${metrics.recall.toFixed(1)}%)`);
    process.exit(1);
}

if (metrics.fpRate > 5) {
    console.error(`\n❌ RED TEAM FAILED: FP Rate too high (${metrics.fpRate.toFixed(1)}%)`);
    process.exit(1);
}

console.log("\n🛡️  RED TEAM PASSED: Sentinel is mathematically robust.");
process.exit(0);
