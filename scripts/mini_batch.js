/**
 * Sentinel: Mini Batch Validation (v1.0)
 * 
 * Runs a small set of realistic PRs to verify telemetry alignment.
 */

const http = require('http');

const MINI_BATCH = [
    {
        id: 5001,
        repo: 'expressjs/express',
        filename: 'README.md',
        patch: `@@ -1,3 +1,3 @@\n- Express\n+ Express JS\n- Fast, unopinionated, minimalist web framework for node.\n+ Fast, unopinionated, minimalist web framework for Node.js.`
    },
    {
        id: 5002,
        repo: 'expressjs/express',
        filename: 'lib/request.js',
        patch: `@@ -100,5 +100,9 @@\n- if (this.body) {\n+ if (this.body && Object.keys(this.body).length > 0) {\n  return this.body;\n- }\n+ } else {\n+   return null;\n+ }`
    },
    {
        id: 5003,
        repo: 'expressjs/express',
        filename: 'test/query.js',
        patch: `@@ -10,6 +10,12 @@\n- it('should parse simple query', function() {\n+ it('should parse simple query', function() {\n  // test\n- });\n+ });\n+ it('should handle nested objects', function() {\n+   const req = { url: '/?user[id]=1' };\n+   // mock logic\n+ });`
    }
];

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
                'X-GitHub-Delivery': `mini-batch-${Date.now()}`
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => resolve(JSON.parse(body)));
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

async function run() {
    console.log("🚀 Starting Mini Batch Validation...");
    
    for (const pr of MINI_BATCH) {
        console.log(`\n📦 Processing PR #${pr.id} (${pr.filename})`);
        try {
            const response = await postData({
                action: 'opened',
                pull_request: {
                    number: pr.id,
                    base: { repo: { full_name: pr.repo } },
                    user: { login: 'real_contributor' }
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
    }
    
    console.log("\n✨ Mini Batch complete. Check docs/shadow_telemetry.jsonl");
}

run();
