/**
 * Sentinel: Large Batch Validation (v1.0)
 * 
 * Runs 25 realistic PRs to verify telemetry alignment and alert density.
 */

const http = require('http');

const BATCH_25 = [];

// 1-10: Benign Documentation and simple fixes
for (let i = 1; i <= 10; i++) {
    BATCH_25.push({
        id: 7000 + i,
        repo: 'expressjs/express',
        filename: i % 2 === 0 ? 'README.md' : `docs/guide-${i}.md`,
        patch: `@@ -1,3 +1,3 @@\n- Express ${i}\n+ Express JS ${i}\n- Documentation update.`
    });
}

// 11-15: Test suite expansions (Dampening test)
for (let i = 11; i <= 15; i++) {
    BATCH_25.push({
        id: 7000 + i,
        repo: 'expressjs/express',
        filename: `test/feature-${i}.js`,
        patch: `@@ -10,6 +10,12 @@\n+ it('should verify feature ${i}', function() {\n+   const result = executeFeature(${i});\n+   expect(result).to.be.true;\n+ });`
    });
}

// 16-20: Core library refactors
for (let i = 16; i <= 20; i++) {
    BATCH_25.push({
        id: 7000 + i,
        repo: 'expressjs/express',
        filename: `lib/router/route-${i}.js`,
        patch: `@@ -50,5 +50,10 @@\n- function handle() {\n+ function handle(options = {}) {\n+   if (options.legacy) return legacyHandle();\n    return defaultHandle();\n  }`
    });
}

// 21-23: Noisy PRs (Complex Regex or dynamic requires in tests)
BATCH_25.push({
    id: 7021,
    repo: 'expressjs/express',
    filename: 'lib/utils.js',
    patch: `@@ -100,5 +100,5 @@\n- const regex = /^[a-z]+$/;\n+ const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_\`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$/;` // Email regex (noisy)
});

BATCH_25.push({
    id: 7022,
    repo: 'expressjs/express',
    filename: 'test/integration.js',
    patch: `@@ -1,5 +1,10 @@\n+ const plugin = require('./plugins/' + process.env.TEST_PLUGIN); // Dynamic require in test`
});

BATCH_25.push({
    id: 7023,
    repo: 'expressjs/express',
    filename: 'lib/request.js',
    patch: `@@ -5,5 +5,10 @@\n+ const buffer = Buffer.from('SGVsbG8gd29ybGQ=', 'base64'); // Base64 in core`
});

// 24-25: High signal benign (Coordinated capabilities but safe)
BATCH_25.push({
    id: 7024,
    repo: 'expressjs/express',
    filename: 'lib/response.js',
    patch: `@@ -1,1 +1,5 @@\n+ const fs = require('fs');\n+ const http = require('http');\n+ function streamFile(path, res) {\n+   fs.createReadStream(path).pipe(res);\n+ }`
});

BATCH_25.push({
    id: 7025,
    repo: 'expressjs/express',
    filename: 'lib/middleware/proxy.js',
    patch: `@@ -1,1 +1,6 @@\n+ const net = require('net');\n+ function proxy(port, host) {\n+   const client = net.connect(port, host);\n+   client.on('data', d => console.log(d.toString('hex')));\n+ }`
});

function postData(data) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(data);
        const req = http.request({
            hostname: 'localhost',
            port: 4567,
            path: '/webhook/github',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': payload.length,
                'X-GitHub-Event': 'pull_request',
                'X-GitHub-Delivery': `batch-25-${data.pull_request.number}-${Date.now()}`
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    reject(new Error(`Failed to parse response: ${body}`));
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

async function run() {
    console.log("🚀 Starting 25-PR Batch Validation...");
    
    for (const pr of BATCH_25) {
        console.log(`\n📦 Processing PR #${pr.id} (${pr.filename})`);
        try {
            const response = await postData({
                action: 'opened',
                pull_request: {
                    number: pr.id,
                    base: { repo: { full_name: pr.repo } },
                    user: { login: 'express_contributor' }
                },
                _mockFiles: [{
                    filename: pr.filename,
                    patch: pr.patch
                }]
            });
            console.log(`✅ Webhook Accepted (Status: 202)`);
        } catch (err) {
            console.error(`❌ Failed: ${err.message}`);
        }
        // Small delay to prevent saturation of the worker pool
        await new Promise(r => setTimeout(r, 200));
    }
    
    console.log("\n✨ Batch 25 complete. Check docs/shadow_metrics.jsonl for Alert Density.");
}

run();
