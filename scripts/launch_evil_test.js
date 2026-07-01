/**
 * Sentinel: Launcher for Evil Stress Test
 */
const { spawn } = require('child_process');
const path = require('path');

const server = spawn('node', ['src/ui/backend/shadow_webhook.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, PORT: '4567' }
});

server.stdout.on('data', (data) => {
    console.log(`[SERVER] ${data}`);
});

server.stderr.on('data', (data) => {
    console.error(`[SERVER ERROR] ${data}`);
});

setTimeout(() => {
    console.log("🚀 Starting Evil Test...");
    const test = spawn('node', ['scripts/test_evil_pr.js'], {
        cwd: path.resolve(__dirname, '..')
    });

    test.stdout.on('data', (data) => {
        console.log(`[TEST] ${data}`);
    });

    test.stderr.on('data', (data) => {
        console.error(`[TEST ERROR] ${data}`);
    });

    test.on('close', (code) => {
        console.log(`[TEST] Finished with code ${code}`);
        console.log("Shutting down server in 10s...");
        setTimeout(() => server.kill(), 10000);
    });
}, 3000);
