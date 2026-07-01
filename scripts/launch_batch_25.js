/**
 * Sentinel: Launcher for 25-PR Batch Validation
 */
const { spawn } = require('child_process');
const path = require('path');

console.log("🛡️ Starting Sentinel Shadow Receiver on port 4567...");
const server = spawn('node', ['src/ui/backend/shadow_webhook.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, PORT: '4567' }
});

server.stdout.on('data', (data) => {
    // Suppress high volume logs, only show shadow processing
    const str = data.toString();
    if (str.includes('[SHADOW]') || str.includes('[WEBHOOK]')) {
        process.stdout.write(`[SERVER] ${str}`);
    }
});

server.stderr.on('data', (data) => {
    console.error(`[SERVER ERROR] ${data}`);
});

setTimeout(() => {
    console.log("\n🚀 Launching 25-PR Batch...");
    const test = spawn('node', ['scripts/batch_25.js'], {
        cwd: path.resolve(__dirname, '..')
    });

    test.stdout.on('data', (data) => {
        process.stdout.write(`[TEST] ${data}`);
    });

    test.stderr.on('data', (data) => {
        console.error(`[TEST ERROR] ${data}`);
    });

    test.on('close', (code) => {
        console.log(`\n[TEST] Finished with code ${code}`);
        console.log("Waiting 15s for all async telemetry to flush...");
        setTimeout(() => {
            console.log("Shutting down server.");
            server.kill();
            process.exit(0);
        }, 15000);
    });
}, 5000);
