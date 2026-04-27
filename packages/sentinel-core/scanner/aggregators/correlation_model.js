/**
 * Sentinel: Signal Correlation Model (v1.2)
 *
 * Implements granular dampening logic to prevent risk overestimation
 * when multiple security signals are linked by context (same package, file, or type).
 */

'use strict';

const DAMPENING_FACTORS = {
    SAME_PACKAGE: 0.60,
    SAME_FILE: 0.70,
    SAME_CATEGORY: 0.85
};

class CorrelationModel {
    /**
     * Calculates the dampening factor for a signal based on its relationship 
     * with previously processed signals in a decision domain.
     * 
     * @param {Object} signal - The current signal being evaluated
     * @param {Object[]} domainSignals - Signals already present in this domain/context
     * @returns {number} The multiplier (0.0 - 1.0) to be applied to the score
     */
    static getDampeningFactor(signal, domainSignals = []) {
        if (!domainSignals || domainSignals.length === 0) return 1.0;

        let lowestFactor = 1.0;

        for (const prev of domainSignals) {
            // Priority 1: Same Package (High Redundancy)
            if (signal.package && prev.package && signal.package === prev.package) {
                lowestFactor = Math.min(lowestFactor, DAMPENING_FACTORS.SAME_PACKAGE);
                continue;
            }

            // Priority 2: Same File
            if (signal._file && prev._file && signal._file === prev._file) {
                lowestFactor = Math.min(lowestFactor, DAMPENING_FACTORS.SAME_FILE);
                continue;
            }

            // Priority 3: Same Category (Functional Overlap)
            if (signal.category && prev.category && signal.category === prev.category) {
                lowestFactor = Math.min(lowestFactor, DAMPENING_FACTORS.SAME_CATEGORY);
            }
        }

        return lowestFactor;
    }

    /**
     * Groups signals by their "Dependency Domain" to facilitate aggregate analysis.
     * @param {Object[]} signals 
     * @returns {Map<string, Object[]>}
     */
    static groupSignalsByDomain(signals) {
        const domains = new Map();
        
        signals.forEach(s => {
            const domainKey = s.package || s._file || 'global';
            if (!domains.has(domainKey)) domains.set(domainKey, []);
            domains.get(domainKey).push(s);
        });

        return domains;
    }
}

module.exports = CorrelationModel;
