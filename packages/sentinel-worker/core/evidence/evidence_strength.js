/**
 * Sentinel: Evidence Strength (v6.0)
 * 
 * Calculates hierarchical confidence based on sensor diversity and causal depth.
 */

'use strict';

class EvidenceStrength {
    /**
     * Calculates semantic confidence for a finding or chain.
     */
    static calculate(evidence) {
        const {
            provenance = 'HISTORICAL',
            sensors = 1,
            chainDepth = 1,
            isDynamic = false,
            isNewInDiff = false
        } = evidence;

        // Weights
        const weights = {
            provenance: 0.25,
            sensorDiversity: 0.20,
            chainDepth: 0.20,
            dynamicSupport: 0.20,
            novelty: 0.15
        };

        // Score components
        const pScore = this._provenanceScore(provenance);
        const sScore = Math.min(1.0, (sensors - 1) * 0.4 + 0.5); // 1 sensor = 0.5, 2 = 0.9, 3+ = 1.0
        const dScore = Math.min(1.0, (chainDepth - 1) * 0.3 + 0.4); // depth 1 = 0.4, 2 = 0.7, 3+ = 1.0
        const dynScore = isDynamic ? 1.0 : 0.4;
        const nScore = isNewInDiff ? 1.0 : 0.6;

        const total = 
            weights.provenance * pScore +
            weights.sensorDiversity * sScore +
            weights.chainDepth * dScore +
            weights.dynamicSupport * dynScore +
            weights.novelty * nScore;

        return Math.max(0.1, Math.min(0.99, total));
    }

    static _provenanceScore(prov) {
        switch (prov) {
            case 'SANDBOX_CONFIRMATION': return 1.0;
            case 'RUNTIME_TELEMETRY':    return 0.9;
            case 'DIFF_NEW':             return 0.8;
            case 'PRODUCTION_FILE':      return 0.7;
            case 'BENIGN_NOISE':         return 0.3;
            case 'TEST_FIXTURE':         return 0.2;
            case 'DOC_EXAMPLE':          return 0.2;
            default:                     return 0.5;
        }
    }
}

module.exports = EvidenceStrength;
