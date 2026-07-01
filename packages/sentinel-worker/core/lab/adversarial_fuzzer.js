/**
 * Sentinel: Adversarial Fuzzer (v1.0)
 * 
 * Generates thousands of malicious variants using composable transformations.
 */

'use strict';

class AdversarialFuzzer {
    constructor() {
        this.transforms = {
            'split': (s) => {
                if (s.length < 4) return s;
                const mid = Math.floor(s.length / 2);
                return `['${s.substring(0, mid)}','${s.substring(mid)}'].join('')`;
            },
            'reverse': (s) => `['${s.split('').reverse().join('')}'].reverse().join('')`,
            'hex': (s) => `Buffer.from('${Buffer.from(s).toString('hex')}', 'hex').toString()`,
            'base64': (s) => `Buffer.from('${Buffer.from(s).toString('base64')}', 'base64').toString()`,
            'char_code': (s) => `String.fromCharCode(${s.split('').map(c => c.charCodeAt(0)).join(',')})`,
            'constructor': (s) => `([].filter.constructor)('${s}')()`
        };
    }

    /**
     * Mutates a payload through multiple levels of indirection.
     */
    fuzz(payload, depth = 2) {
        let result = payload;
        const keys = Object.keys(this.transforms);
        
        for (let i = 0; i < depth; i++) {
            const transformKey = keys[Math.floor(Math.random() * keys.length)];
            const transform = this.transforms[transformKey];
            
            // Apply transform to any string literals in the payload
            result = result.replace(/['"]([^'"]+)['"]/g, (match, p1) => {
                return transform(p1);
            });
        }
        
        return result;
    }

    /**
     * Generates a batch of fuzzed payloads.
     */
    generateBatch(payload, count = 10) {
        const batch = new Set();
        batch.add(payload);
        let iterations = 0;
        while (batch.size < count && iterations < 100) {
            batch.add(this.fuzz(payload, 1 + Math.floor(Math.random() * 2)));
            iterations++;
        }
        return Array.from(batch);
    }
}

module.exports = new AdversarialFuzzer();
