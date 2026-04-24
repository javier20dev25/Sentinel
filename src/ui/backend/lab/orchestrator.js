/**
 * Sentinel Adversarial Lab (SAL): Lab Orchestrator (v1.0)
 * 
 * Manages the Adversarial Training loop (Attacker vs Defender).
 * Collects metrics and identifies performance regressions or detection gaps.
 */

'use strict';

const attacker = require('./attacker');
const profiler = require('./profiler');
const SPL = require('../spl/index');
const fs = require('fs');
const path = require('path');

class LabOrchestrator {
    constructor() {
        this.resultsPath = path.join(__dirname, 'adversarial_results.json');
        this.history = [];
    }

    /**
     * Executes a batch of adversarial simulations.
     * @param {number} iterations - Number of attacks to simulate.
     * @param {number} intensity - Mutation depth [0.0 - 1.0].
     */
    async runSession(iterations = 10, intensity = 0.5) {
        console.log(`[SAL] Starting Adversarial Session: ${iterations} iterations at intensity ${intensity}`);
        
        for (let i = 0; i < iterations; i++) {
            const attack = attacker.generate(intensity);
            
            // 1. Profile Sentinel Analysis
            profiler.start();
            const result = await this._executeSentinel(attack);
            const metrics = profiler.stop();

            // 2. Evaluate Performance
            const record = {
                iteration: i,
                attack_type: attack.type,
                attack_payload: attack.raw,
                verdict: result.verdict,
                detected: result.verdict === 'block',
                metrics
            };

            this.history.push(record);
            process.stdout.write(record.detected ? '🛡️' : '❌');
        }

        this._persist();
        console.log(`\n[SAL] Session completed. Results saved to: ${this.resultsPath}`);
    }

    async _executeSentinel(attack) {
        // Simulated Playbook for validation
        const playbook = `
            workflow "adversarial-defense" {
                target package
                profile strict
                when install package {
                    run supply_chain_shield
                    if risk.score > 0.5 { block } else { allow }
                }
            }
        `;

        const context = {
            event: { type: 'install' },
            package: { name: 'test-pkg', content: attack.raw }
        };

        const result = await SPL.run(playbook, context);
        return { verdict: result.results[0]?.verdict || 'allow' };
    }

    _persist() {
        fs.writeFileSync(this.resultsPath, JSON.stringify(this.history, null, 2));
    }
}

module.exports = new LabOrchestrator();
