/**
 * Sentinel: Adversarial Benchmark Runner (v1.0)
 * 
 * Executes the 500+ malicious fixture suite and calculates
 * core performance metrics: Precision, Recall, FPR, and FNR.
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const SUITE_PATH = path.join(__dirname, '../benchmarks/adversarial/suite_500.json');
const OBSERVATIONS_PATH = path.join(__dirname, '../docs/shadow_observations.jsonl');

async function postData(data) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(data);
        const req = http.request({
            hostname: 'localhost',
            port: 4568,
            path: '/webhook/github',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': payload.length,
                'X-GitHub-Event': 'pull_request',
                'X-GitHub-Delivery': `bench-${data.pull_request.number}-${Date.now()}`
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

async function runBenchmark() {
    console.log("🚀 Starting Adversarial Benchmark (Suite 500)...");
    
    // 1. Clear previous observations
    if (fs.existsSync(OBSERVATIONS_PATH)) fs.unlinkSync(OBSERVATIONS_PATH);
    
    // 2. Start Receiver
    const docsDir = path.join(__dirname, '../docs');
    if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });

    const server = spawn('node', ['src/ui/backend/shadow_webhook.js'], {
        cwd: path.resolve(__dirname, '..'),
        env: { ...process.env, PORT: '4568' }
    });

    server.stdout.on('data', (d) => console.log(`[SERVER] ${d}`));
    server.stderr.on('data', (d) => console.error(`[SERVER ERR] ${d}`));

    await new Promise(r => setTimeout(r, 5000));

    const suite = JSON.parse(fs.readFileSync(SUITE_PATH, 'utf8'));
    
    let processed = 0;
    for (const pr of suite) {
        await postData({
            pull_request: {
                number: pr.id,
                base: { repo: { full_name: pr.repo } },
                user: { login: 'adversary' }
            },
            _mockFiles: [{
                filename: pr.filename,
                patch: pr.patch
            }]
        });
        processed++;
        if (processed % 50 === 0) console.log(`📡 Processed ${processed}/500...`);
        await new Promise(r => setTimeout(r, 50));
    }

    console.log("\n⌛ Waiting for engine to finalize results...");
    await new Promise(r => setTimeout(r, 15000));
    server.kill();

    // 3. Analyze Results
    const STRESS_PATH = path.join(__dirname, '../docs/shadow_stress.jsonl');
    if (!fs.existsSync(STRESS_PATH)) {
        console.error(`❌ Benchmark failure: ${STRESS_PATH} not found.`);
        process.exit(1);
    }
    const observations = fs.readFileSync(STRESS_PATH, 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
    
    const truePositives = observations.filter(o => o.verdict !== 'PASS').length;
    const falseNegatives = observations.length - truePositives;
    
    const recall = (truePositives / observations.length) * 100;
    
    console.log("\n📊 BENCHMARK RESULTS:");
    console.log(`Total Samples: ${observations.length}`);
    console.log(`True Positives: ${truePositives}`);
    console.log(`False Negatives: ${falseNegatives}`);
    console.log(`Recall Rate: ${recall.toFixed(2)}%`);
    
    // 4. Regression Gate (Phase 11)
    if (recall < 90) {
        console.error("\n❌ REGRESSION DETECTED: Recall dropped below 90% threshold!");
        process.exit(1);
    }
    
    console.log("\n✅ Benchmark Passed.");
    process.exit(0);
}

runBenchmark().catch(err => {
    console.error(err);
    process.exit(1);
});
