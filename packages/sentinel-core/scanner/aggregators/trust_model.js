/**
 * Sentinel: Federated Trust Model (v1.0)
 * 
 * Manages the reliability scoring for intelligence sources.
 * Prevents system poisoning by applying weighted trust factors to global signals.
 */

'use strict';

class TrustModel {
    constructor() {
        this.weights = {
            INTERNAL: 1.0,      // Data from the same organization/local repo
            VERIFIED: 0.8,      // Trusted partners or official Sentinel feeds
            COMMUNITY: 0.3,     // General telemetry from unknown sources
            UNTRUSTED: 0.0      // Blacklisted sources
        };
    }

    /**
     * Retrieves the weight for a specific source category.
     * @param {string} category - INTERNAL, VERIFIED, COMMUNITY, UNTRUSTED
     * @returns {number} Trust multiplier [0.0 - 1.0]
     */
    getWeight(category) {
        return this.weights[category] || this.weights.COMMUNITY;
    }

    /**
     * Resolves the source category for a given source ID.
     * Initial implementation uses prefix-based resolution.
     */
    resolveCategory(sourceId) {
        if (!sourceId) return 'COMMUNITY';
        if (sourceId.startsWith('local:')) return 'INTERNAL';
        if (sourceId.startsWith('sentinel-official:')) return 'VERIFIED';
        return 'COMMUNITY';
    }

    /**
     * Applies the trust weighting to a raw risk signal.
     * @param {number} rawScore - The initial risk score [0.0 - 1.0]
     * @param {string} sourceId - The identifier of the reporting source
     * @returns {number} Weighted risk score
     */
    calculateWeightedScore(rawScore, sourceId) {
        const category = this.resolveCategory(sourceId);
        const weight = this.getWeight(category);
        return rawScore * weight;
    }
}

module.exports = new TrustModel();
