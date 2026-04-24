/**
 * Sentinel Adversarial Lab (SAL): Public Attacker (v0.1)
 * 
 * A simplified version of the attacker for the public repository.
 * Contains basic synthetic payloads for benchmarking.
 */

'use strict';

class PublicAttacker {
    generate(intensity = 0.5, strategy = 'standard') {
        const payloads = [
            { type: 'test', template: 'console.log("sentinel-test-payload");' },
            { type: 'test', template: 'const x = "benign-code";' }
        ];

        const base = payloads[Math.floor(Math.random() * payloads.length)];
        return {
            type: base.type,
            strategy: 'standard',
            raw: base.template,
            intensity: 0.1
        };
    }
}

module.exports = new PublicAttacker();
