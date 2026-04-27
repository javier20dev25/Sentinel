/**
 * Sentinel: Security Gate Orchestrator
 * 
 * Maps filesystem triggers (modified files, artifacts, configurations) to 
 * adaptive security gate levels. 
 */

'use strict';

const path = require('path');

/**
 * Gate Levels Definition:
 * 0: FAST gate (Normal source, non-critical)
 * 1: STANDARD gate (Relevant source changes)
 * 2: DEPENDENCY / SUPPLY CHAIN gate (Triggered by manifests/lockfiles)
 * 3: ARTIFACT / BINARY gate (Triggered by binaries, large files)
 * 4: FORENSIC gate (High suspicion or manual trigger)
 */

const TRIGGERS = {
    LEVEL_2: [
        'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
        'requirements.txt', 'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
        '.npmrc', '.yarnrc', '.yarnrc.yml'
    ],
    LEVEL_3: [
        '.exe', '.dll', '.wasm', '.so', '.dylib', '.bin', '.dat', '.node'
    ]
};

class GateOrchestrator {
    /**
     * Determine the required gate level based on a collection of file paths.
     * 
     * @param {string[]} files - List of modified/relevant file paths
     * @returns {Object} { level: number, triggers: string[], reason: string }
     */
    static resolveGateLevel(files) {
        if (!files || files.length === 0) {
            return { level: 0, triggers: [], reason: 'No files provided, defaulting to Fast Gate' };
        }

        const detectedTriggers = {
            level2: [],
            level3: []
        };

        for (const file of files) {
            const basename = path.basename(file);
            const ext = path.extname(file).toLowerCase();

            // Check Level 2 (Dependency / Supply Chain)
            if (TRIGGERS.LEVEL_2.includes(basename)) {
                detectedTriggers.level2.push(basename);
            }

            // Check Level 3 (Artifacts / Binaries)
            if (TRIGGERS.LEVEL_3.includes(ext)) {
                detectedTriggers.level3.push(basename);
            }
        }

        // Logic of Escalation
        if (detectedTriggers.level3.length > 0) {
            return {
                level: 3,
                triggers: detectedTriggers.level2.concat(detectedTriggers.level3),
                reason: `Binary artifacts or suspicious extensions detected: ${detectedTriggers.level3.join(', ')}`
            };
        }

        if (detectedTriggers.level2.length > 0) {
            return {
                level: 2,
                triggers: detectedTriggers.level2,
                reason: `Supply chain manifests or lockfiles modified: ${detectedTriggers.level2.join(', ')}`
            };
        }

        // Default to Standard or Fast
        if (files.length > 5) {
            return { level: 1, triggers: [], reason: 'Relevant source changes detected' };
        }

        return { level: 0, triggers: [], reason: 'Normal minor changes' };
    }

    /**
     * Get the human-readable label for a level.
     */
    static getLevelLabel(level) {
        const labels = [
            'FAST GATE',
            'STANDARD GATE',
            'DEPENDENCY GATE',
            'ARTIFACT GATE',
            'FORENSIC GATE'
        ];
        return labels[level] || 'UNKNOWN GATE';
    }
}

module.exports = GateOrchestrator;
