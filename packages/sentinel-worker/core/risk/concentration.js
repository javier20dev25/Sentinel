/**
 * Sentinel: Risk Concentration (v6.0)
 * 
 * Calculates risk distribution and coordination metrics.
 */

'use strict';

class RiskConcentrator {
    /**
     * Calculates the Concentration Index and Top-K metrics.
     */
    static analyze(fileRisks) {
        if (!fileRisks || fileRisks.length === 0) return { concentration: 0, top1: 0, top3: 0, top5: 0 };

        const sorted = [...fileRisks].sort((a, b) => b - a);
        const total = sorted.reduce((sum, r) => sum + r, 0);

        const top1 = sorted[0] || 0;
        const top3 = sorted.slice(0, 3).reduce((sum, r) => sum + r, 0) / 3;
        const top5 = sorted.slice(0, 5).reduce((sum, r) => sum + r, 0) / 5;

        // Concentration Index: Ratio of Top-3 risk to total risk (normalized)
        const concentration = total > 0 ? (sorted.slice(0, 3).reduce((sum, r) => sum + r, 0) / total) : 0;

        return {
            concentration: Math.min(1.0, concentration),
            top1,
            top3,
            top5,
            entropy: this._calculateEntropy(sorted)
        };
    }

    /**
     * Calculates risk entropy (lower entropy = more coordinated/concentrated threat).
     */
    static _calculateEntropy(risks) {
        const sum = risks.reduce((a, b) => a + b, 0);
        if (sum === 0) return 1.0;
        
        let entropy = 0;
        for (const r of risks) {
            if (r === 0) continue;
            const p = r / sum;
            entropy -= p * Math.log2(p);
        }
        
        // Normalize entropy based on number of samples
        const maxEntropy = Math.log2(risks.length || 1) || 1;
        return entropy / maxEntropy;
    }
}

module.exports = RiskConcentrator;
