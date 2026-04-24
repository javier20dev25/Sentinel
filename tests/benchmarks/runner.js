const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

// Generators
const generateGarbage = require('./generators/garbage');
const generateSymlinks = require('./generators/symlinks');
const generateSignals = require('./generators/signals');

const HISTORY_PATH = path.join(__dirname, 'history.json');
const EXPECTATIONS = {
    garbage: { minFilesPerSec: 300 },
    symlinks: { recursionBlocked: true, escapeBlocked: true },
    signals: { minRecall: 0.8, minPrecision: 0.7 }
};

class BenchmarkRunner {
    constructor() {
        const fixtureDir = path.join(__dirname, 'fixtures');
        if (!fs.existsSync(fixtureDir)) fs.mkdirSync(fixtureDir, { recursive: true });
        this.tmpDir = fs.mkdtempSync(path.join(fixtureDir, 'bench-'));
        this.results = {
            timestamp: new Date().toISOString(),
            scenarios: {}
        };
    }

    async run() {
        console.log(`\n\x1b[36m=== Sentinel Benchmark Engine (Phase 9.5) ===\x1b[0m`);
        console.log(`Working Directory: ${this.tmpDir}\n`);

        try {
            await this.testGarbage();
            await this.testSymlinks();
            await this.testSignals();
            
            this.report();
            this.persist();
        } finally {
            this.cleanup();
        }
    }

    async runCommand(cmd) {
        try {
            return execSync(cmd, { stdio: 'pipe', maxBuffer: 50 * 1024 * 1024 }).toString();
        } catch (e) {
            if (e.stdout) return e.stdout.toString();
            throw e;
        }
    }

    parseJSON(output) {
        const jsonStart = output.indexOf('{');
        if (jsonStart === -1) throw new Error("No JSON found in output: " + output);
        return JSON.parse(output.substring(jsonStart));
    }

    async testGarbage() {
        console.log(`[1/3] Scenario: Garbage Bin (Stress Test)...`);
        const garbageDir = path.join(this.tmpDir, 'garbage');
        await generateGarbage(garbageDir);

        const start = Date.now();
        const output = await this.runCommand(`node src/ui/cli/index.js scan "${garbageDir}" --json`);
        const duration = Date.now() - start;
        
        const data = this.parseJSON(output);
        const fps = Math.round((data.filesScanned / (duration / 1000)));

        const status = fps >= EXPECTATIONS.garbage.minFilesPerSec ? 'PASS' : 'FAIL';
        this.results.scenarios.garbage = { status, fps, duration, files: data.filesScanned };
        console.log(`      Status: ${status === 'PASS' ? '✅' : '❌'} (${fps} files/sec)\n`);
    }

    async testSymlinks() {
        console.log(`[2/3] Scenario: Symlink Maze (Security Guard)...`);
        const symDir = path.join(this.tmpDir, 'symlinks');
        await generateSymlinks(symDir);

        const start = Date.now();
        const output = await this.runCommand(`node src/ui/cli/index.js scan "${symDir}" --json`);
        const duration = Date.now() - start;
        
        const data = this.parseJSON(output);
        
        // Validation: Ensure no home folder files are in the scan (Escape blocked)
        const escaped = data.rawAlerts?.some(a => a._fullPath && !a._fullPath.startsWith(this.tmpDir));
        const status = !escaped ? 'PASS' : 'FAIL';

        this.results.scenarios.symlinks = { status, duration, escaped };
        console.log(`      Status: ${status === 'PASS' ? '✅' : '❌'} (No escapes detected)\n`);
    }

    async testSignals() {
        console.log(`[3/3] Scenario: Signal Attack (Precision/Recall)...`);
        const signalDir = path.join(this.tmpDir, 'signals');
        const trapCount = await generateSignals(signalDir);

        const output = await this.runCommand(`node src/ui/cli/index.js scan "${signalDir}" --json`);
        const data = this.parseJSON(output);

        const detections = data.rawAlerts || [];
        const validDetections = detections.filter(a => ['package.json', 'app.js', 'config.json', 'test_ci.js', 'utils.ts'].includes(a._file)).length;
        
        // In this controlled test, validDetections should map to the files we trapped
        const recall = validDetections / trapCount;
        const precision = detections.length > 0 ? validDetections / detections.length : 1;

        const status = (recall >= EXPECTATIONS.signals.minRecall && precision >= EXPECTATIONS.signals.minPrecision) ? 'PASS' : 'FAIL';
        
        this.results.scenarios.signals = { status, recall, precision, detections: detections.length };
        console.log(`      Status: ${status === 'PASS' ? '✅' : '❌'} (Recall: ${Math.round(recall*100)}% | Precision: ${Math.round(precision*100)}%)\n`);
    }

    report() {
        console.log(`\x1b[32m=== Final Report ===\x1b[0m`);
        Object.entries(this.results.scenarios).forEach(([name, res]) => {
            const color = res.status === 'PASS' ? '\x1b[32m' : '\x1b[31m';
            console.log(`${name.padEnd(15)} → ${color}${res.status}\x1b[0m`);
        });
        const allPass = Object.values(this.results.scenarios).every(s => s.status === 'PASS');
        console.log(`\nOverall Stability: ${allPass ? '✅ STABLE' : '❌ UNSTABLE'}\n`);
    }

    persist() {
        let history = [];
        if (fs.existsSync(HISTORY_PATH)) {
            try { history = JSON.parse(fs.readFileSync(HISTORY_PATH)); } catch(e) {}
        }
        history.push(this.results);
        fs.writeFileSync(HISTORY_PATH, JSON.stringify(history.slice(-10), null, 2));
    }

    cleanup() {
        console.log(`Cleaning up ${this.tmpDir}...`);
        try {
            if (this.tmpDir) fs.rmSync(this.tmpDir, { recursive: true, force: true });
        } catch(e) {}
    }
}

const runner = new BenchmarkRunner();
runner.run();
