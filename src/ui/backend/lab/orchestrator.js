/**
 * Sentinel Adversarial Lab (SAL): Lab Orchestrator (v1.1)
 * 
 * Implements Gradual Difficulty Scaling and Closed-Loop Feedback.
 * Tracks performance across levels to drive engine evolution.
 */

'use strict';

const attacker = require('./attacker');
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

    async runSession(iterations = 10) {
        console.clear();
        console.log(`\x1b[35m[SAL] ADVERSARIAL EVOLUTION SESSION STARTED\x1b[0m`);
        console.log(`\x1b[2mTracking real-time metrics and detection performance...\x1b[0m\n`);

        for (let i = 0; i < iterations; i++) {
            const intensity = this.levelManager.getIntensity();
            const attack = attacker.generate(intensity);
            
            // 1. Initial Analysis Pass
            profiler.start();
            let result = await this._executeSentinel(attack, 'standard');
            let metrics = profiler.stop();

            // 2. Hint & Retry Mechanism (if failure)
            let retryResult = null;
            if (result.verdict !== 'block') {
                // Attacker reveals the mutation type as a 'hint'
                const hint = attack.type; 
                retryResult = await this._executeSentinel(attack, 'boosted', hint);
            }

            // 3. Register Outcome
            const status = this.levelManager.registerResult(result.verdict === 'block');
            
            const record = {
                timestamp: new Date().toISOString(),
                level: this.levelManager.currentLevel,
                attack: { type: attack.type, payload: attack.raw, intensity },
                outcome: { 
                    detected: result.verdict === 'block', 
                    verdict: result.verdict,
                    retry_detected: retryResult?.verdict === 'block'
                },
                metrics,
                status_change: status.action
            };

            this._displayIteration(record);
            this.history.push(record);
            this._persist();
        }

        console.log(`\n\x1b[32m[SAL] Session completed. Data persisted in adversarial_results.json\x1b[0m`);
    }

    async _executeSentinel(attack, mode = 'standard', hint = null) {
        // In 'boosted' mode, we lower the block threshold to simulate 'knowing the hint'
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
        const icon = record.outcome.detected ? '\x1b[32m🛡️ PASS\x1b[0m' : '\x1b[31m❌ FAIL\x1b[0m';
        const lvl = `[LVL ${record.level}]`;
        const res = `Lat: ${record.metrics.latency_ms}ms | Mem: ${record.metrics.memory_delta_bytes}B`;
        const change = record.status_change !== 'STAY' ? `\x1b[33m >> ${record.status_change}!\x1b[0m` : '';

        console.log(`${lvl} ${icon} | ${res} | Type: ${record.attack.type}${change}`);
        if (!record.outcome.detected && record.outcome.retry_detected) {
            console.log(`   \x1b[2m-> Hint Recovery: SUCCESS (Detected with lowered threshold)\x1b[0m`);
        }
    }

    _persist() {
        fs.writeFileSync(this.resultsPath, JSON.stringify(this.history, null, 2));
    }
}

module.exports = new LabOrchestrator();
