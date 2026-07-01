/**
 * Sentinel: Evil PR Stress Test (v1.0)
 * 
 * Sends synthetic "malicious" payloads to the webhook to test 
 * resilience against ReDoS, memory exhaustion, and malformed patches.
 */

const http = require('http');

const WEBHOOK_URL = 'http://localhost:4567/webhook/github';

async function postData(data) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify(data);
        const req = http.request('http://localhost:4567/webhook/github', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
                'x-github-delivery': `stress-${Date.now()}-${Math.random()}`
            }
        }, (res) => {
            let resData = '';
            res.on('data', chunk => resData += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data: resData }));
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

const EVIL_PAYLOADS = [
    {
        id: 1,
        name: 'ReDoS: Exponential Backtracking',
        filename: 'redos_attack.js',
        // This is a classic ReDoS pattern if evaluated by a vulnerable regex
        patch: `@@ -1,1 +1,1 @@\n- console.log("start");\n+ const regex = / (a+)+$/; regex.test("${"a".repeat(100)}!");`
    },
    {
        id: 2,
        name: 'Memory: Gigantic Base64 Blob',
        filename: 'asset_blob.bin',
        patch: `@@ -1,1 +1,1 @@\n- []\n+ const data = "${"Z".repeat(100000)}";`
    },
    {
        id: 3,
        name: 'Malformed: Garbage Diff',
        filename: 'corrupted.txt',
        patch: `this is not a diff at all just garbage data meant to break the parser`
    },
    {
        id: 4,
        name: 'Supply Chain: Obfuscated Install Hook',
        filename: 'package.json',
        patch: `@@ -10,1 +10,1 @@\n- "scripts": {}\n+ "scripts": { "postinstall": "node -e 'eval(Buffer.from(\\"Y2hpbGRfcHJvY2Vzcy5zcGF3bihiYXNoKVxu\\",\\"base64\\").toString())' " }`
    },
    {
        id: 5,
        name: 'Renamed File Context Test',
        filename: 'tests/renamed_to_test.js',
        patch: `@@ -1,1 +1,1 @@\n- function old() {}\n+ eval(process.env.SECRET);`
    }
];

async function run() {
    console.log("🔥 Starting Evil PR Stress Test...");
    
    for (const payload of EVIL_PAYLOADS) {
        console.log(`\n🧪 Testing: ${payload.name}`);
        try {
            const response = await postData({
                action: 'opened',
                is_stress_test: true, // Signal to webhook to use isolation
                pull_request: {
                    number: 666 + payload.id,
                    base: { repo: { full_name: 'attacker/chaos-repo' } },
                    user: { login: 'chaos_bot' }
                },
                // Mocking the files fetch in the webhook
                _mockFiles: [{
                    filename: payload.filename,
                    patch: payload.patch
                }]
            });
            console.log(`✅ Webhook Accepted (Status: ${response.status})`);
        } catch (e) {
            console.error(`❌ Webhook Failed: ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 1000));
    }
}

run();
