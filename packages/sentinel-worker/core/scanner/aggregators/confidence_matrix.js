/**
 * Sentinel: Confidence Matrix (v1.2)
 * 
 * Defines source-specific and context-aware confidence factors 
 * to calibrate the weight of security signals.
 */

'use strict';

const CONFIDENCE_LEVELS = {
    INTERNAL: 0.95,        // Direct SARB detection (High Determinism)
    EXTERNAL_NPM: 0.95,    // Historical CVEs / Audit (Fact-based)
    EXTERNAL_AI: 0.60,     // Probabilistic LLM reviews (Advisory)
};

const CONTEXT_MULTIPLIERS = {
    RUNTIME: 1.0,          // Production impact
    DEV: 0.8               // Development/Build tool impact (Slight discount)
};

class ConfidenceMatrix {
    /**
     * Resolves the confidence factor for a given signal.
     * 
     * @param {Object} signal 
     * @returns {number} Confidence factor (0.0 - 1.0)
     */
    static getConfidence(signal) {
        const source = signal.source || 'internal';
        let baseConfidence = CONFIDENCE_LEVELS.INTERNAL;

        if (source.startsWith('external:npm')) {
            baseConfidence = CONFIDENCE_LEVELS.EXTERNAL_NPM;
        } else if (source.startsWith('external:ai')) {
            baseConfidence = CONFIDENCE_LEVELS.EXTERNAL_AI;
        }

        // Apply context multiplier (Runtime vs Dev)
        const isDev = signal.isDevDependency || false;
        const multiplier = isDev ? CONTEXT_MULTIPLIERS.DEV : CONTEXT_MULTIPLIERS.RUNTIME;

        return baseConfidence * multiplier;
    }

    /**
     * Get the default weight mapping for sources.
     */
    static getSourceWeight(source) {
        const weights = {
            'internal': 1.0,
            'external:npm': 0.6,
            'external:ai': 0.3
        };

        // Standardize source name for mapping
        const key = Object.keys(weights).find(k => source.startsWith(k)) || 'internal';
        return weights[key];
    }
}

module.exports = ConfidenceMatrix;
