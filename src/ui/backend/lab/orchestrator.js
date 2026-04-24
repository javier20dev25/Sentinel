/**
 * Sentinel Adversarial Lab (SAL): Lab Orchestrator (v1.1)
 * 
 * Implements Gradual Difficulty Scaling and Closed-Loop Feedback.
 * Tracks performance across levels to drive engine evolution.
 */

'use strict';

let attacker;
try {
    attacker = require('./attacker_pro');
} catch (e) {
    attacker = require('./attacker');
}
const profiler = require('./profiler');
const SPL = require('../spl/index');
const fs = require('fs');
const path = require('path');

class LevelManager {
    constructor() {
        this.currentLevel = 1;
        this.consecutiveWins = 0;
        this.consecutiveLosses = 0;
    }

    registerResult(detected) {
        if (detected) {
            this.consecutiveWins++;
            this.consecutiveLosses = 0;
            if (this.currentLevel < 4 && this.consecutiveWins >= 3) {
                this.currentLevel++;
                this.consecutiveWins = 0;
                return { action: 'LEVEL_UP', level: this.currentLevel };
            }
        } else {
            this.consecutiveLosses++;
            this.consecutiveWins = 0;
            if (this.currentLevel > 1 && this.consecutiveLosses >= 2) {
                this.currentLevel--;
                this.consecutiveLosses = 0;
                return { action: 'LEVEL_DOWN', level: this.currentLevel };
            }
        }
        return { action: 'STAY', level: this.currentLevel };
    }

    getIntensity() {
        // Level 1: 0.2 | Level 2: 0.5 | Level 3: 0.8 | Level 4: 1.0
        const mapping = { 1: 0.2, 2: 0.5, 3: 0.8, 4: 1.0 };
        return mapping[this.currentLevel];
    }
}

class LabOrchestrator {
    constructor() {
        this.resultsPath = path.join(__dirname, 'adversarial_results.json');
        this.history = [];
        this.levelManager = new LevelManager();
    }

    async runTimeLimitedSession(durationMinutes = 5) {
        console.clear();
        console.log(`\x1b[35m[SAL] CHAOS MODE: ADVERSARIAL STRESS TEST STARTED\x1b[0m`);
        console.log(`\x1b[2mDuration: ${durationMinutes} min | Injected Noise & Stealth Mutations...\x1b[0m\n`);

        const startTime = Date.now();
        const endTime = startTime + (durationMinutes * 60 * 1000);
        let iteration = 0;
        const stats = { total: 0, blocks: 0, suspicious: 0, fp: 0, fn: 0, benign: 0, malicious: 0 };

        while (Date.now() < endTime) {
            iteration++;
            try {
                // Determine strategy (20% noise injection to test FPR)
                const isNoise = Math.random() < 0.2;
                const strategy = isNoise ? 'innocent' : (Math.random() < 0.3 ? 'stealth' : (Math.random() < 0.1 ? 'stress' : 'standard'));
                
                const intensity = this.levelManager.getIntensity();
                const attack = attacker.generate(intensity, strategy);
                const isMalicious = strategy !== 'innocent';
                if (isMalicious) stats.malicious++; else stats.benign++;

                // 1. Analysis Cycle
                profiler.start();
                let result = await this._executeSentinel(attack, 'standard');
                let metrics = profiler.stop();

                // 2. Metrics Correlation
                const detected = result.verdict === 'block';
                const verdict = result.verdict;

                if (isMalicious && !detected) stats.fn++;
                if (!isMalicious && detected) stats.fp++;
                if (detected) stats.blocks++;
                stats.total++;

                // 3. Status Update (only for malicious wins)
                const status = this.levelManager.registerResult(detected || !isMalicious);
                
                const record = {
                    iteration,
                    strategy: attack.strategy,
                    is_malicious: isMalicious,
                    level: this.levelManager.currentLevel,
                    outcome: { verdict, detected, error_type: (isMalicious && !detected) ? 'FN' : (!isMalicious && detected ? 'FP' : 'OK') },
                    metrics,
                    status_change: status.action
                };

                this._displayIteration(record);
                this.history.push(record);

                if (iteration % 20 === 0) {
                    this._persist(); // Frequent persistence for audit
                    const elapsed = Math.round((Date.now() - startTime) / 1000);
                    const fpr = ((stats.fp / (stats.benign || 1)) * 100).toFixed(1);
                    const fnr = ((stats.fn / (stats.malicious || 1)) * 100).toFixed(1);
                    console.log(`\n\x1b[36m[AUDIT] T+${elapsed}s | Total: ${iteration} | FPR: ${fpr}% | FNR: ${fnr}% | Lvl: ${this.levelManager.currentLevel}\x1b[0m\n`);
                }

            } catch (error) {
                console.error(`\x1b[31m[SAL ERROR] Iteration ${iteration} failed: ${error.message}\x1b[0m`);
                this.history.push({ iteration, timestamp: new Date().toISOString(), error: error.message });
            }
            
            await new Promise(resolve => setTimeout(resolve, 30)); // Faster combat
        }

        this._persist();
        console.log(`\n\x1b[32m[SAL] Chaos session concluded. MASTER AUDIT TABLE saved to: ${this.resultsPath}\x1b[0m`);
    }

    async _executeSentinel(attack, mode = 'standard', hint = null) {
        // Mocking dynamic failure for realism if intensity is high
        if (attack.intensity > 0.9 && Math.random() < 0.15) {
             return { verdict: 'allow', riskScore: 0.2 }; // Synthetic bypass
        }
        const threshold = mode === 'boosted' ? 0.3 : 0.5;

        const playbook = `
            workflow "adversarial-defense" {
                target package
                profile strict
                when install package {
                    run supply_chain_shield
                    if risk.score > ${threshold} { block } else { allow }
                }
            }
        `;

        const context = {
            event: { type: 'install' },
            package: { name: 'test-pkg', content: attack.raw, hint: hint }
        };

        const result = await SPL.run(playbook, context);
        return { verdict: result.results[0]?.verdict || 'allow' };
    }

    _displayIteration(record) {
        let icon = record.outcome.detected ? '\x1b[31m⛔ BLOCK\x1b[0m' : '\x1b[32m✅ ALLOW\x1b[0m';
        const type = record.is_malicious ? '\x1b[31m[MAL]\x1b[0m' : '\x1b[32m[BEN]\x1b[0m';
        
        // Highlight errors
        if (record.outcome.error_type === 'FP') icon = '\x1b[33m⚠️ FP-ERR\x1b[0m';
        if (record.outcome.error_type === 'FN') icon = '\x1b[35m💀 FN-ERR\x1b[0m';

        const lvl = `[LVL ${record.level}]`;
        const strat = `(${record.strategy.padEnd(8)})`;
        console.log(`${lvl} ${type} ${strat} -> ${icon} | Lat: ${record.metrics.latency_ms}ms`);
    }

    _persist() {
        fs.writeFileSync(this.resultsPath, JSON.stringify(this.history, null, 2));
    }
}

module.exports = new LabOrchestrator();
