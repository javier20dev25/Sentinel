const CONFIG = require('./config');

/**
 * Sentinel Oracle Brain: Scoring Engine (v2.0)
 * 
 * Implements Contextual Weighting and Damped Probabilistic Aggregation.
 * Formula: R = 1 - exp(-Damping * rawRisk)
 */
class ScoringEngine {
    constructor() {
        this.weights = CONFIG.SCORING.CONTEXT_WEIGHTS;
        this.damping = CONFIG.SCORING.DAMPING_FACTOR;
        this.severityMap = CONFIG.SCORING.SEVERITY_MAP;
    }

    /**
     * Calculates the Risk Score for a set of findings in a specific context.
     */
    calculateFileRisk(alerts, fullPath) {
        if (!alerts || alerts.length === 0) return 0;

        const deduplicated = this._deduplicate(alerts, fullPath);
        const weight = this.getContextWeight(fullPath);
        let survivalProbability = 1.0;

        deduplicated.forEach(alert => {
            let p = this.severityMap[alert.severity] || 0.1;
            const isOverridden = CONFIG.SCORING.OVERRIDES.some(o => alert.category === o || (alert.type && alert.type.includes(o)));
            const effectiveWeight = isOverridden ? 1.0 : weight;
            survivalProbability *= (1 - (p * effectiveWeight));
        });

        const rawRisk = 1 - survivalProbability;
        return 1 - Math.exp(-this.damping * rawRisk);
    }

    /**
     * Semantic Deduplication: Groups multiple technical hits into one logical threat.
     */
    _deduplicate(alerts, fullPath) {
        const seen = new Set();
        const unique = [];

        alerts.forEach(a => {
            const category = this._mapCategory(a.type);
            const key = `${fullPath}:${a.line || a.line_number || 0}:${category}`;
            
            if (!seen.has(key)) {
                seen.add(key);
                unique.push({ ...a, category });
            }
        });

        return unique;
    }

    _mapCategory(type = '') {
        if (type.includes('SECRET') || type.includes('KEY')) return 'SECRET';
        if (type.includes('EVAL') || type.includes('EXEC') || type.includes('INJECTION')) return 'EXECUTION';
        if (type.includes('ENTROPY') || type.includes('BASE64') || type.includes('OBFUSCATION') || type.includes('PAYLOAD')) return 'OBFUSCATION';
        if (type.includes('LIFECYCLE') || type.includes('CI_EVASION')) return 'INTEGRITY';
        return 'GENERAL';
    }

    /**
     * Resolves the weighting factor based on directory depth and importance.
     */
    getContextWeight(fullPath) {
        const parts = fullPath.split(/[\\/]/);
        
        // Prioritize specific files (e.g. package.json)
        const filename = parts[parts.length - 1];
        if (this.weights[filename]) return this.weights[filename];

        // Check for directory matches in the path
        for (const dir in this.weights) {
            if (parts.includes(dir)) return this.weights[dir];
        }

        return this.weights['default'];
    }

    /**
     * Aggregates multiple file risks into a Repo Global Score.
     */
    calculateGlobalScore(fileRisks) {
        if (!fileRisks || fileRisks.length === 0) return 0;
        
        // Aggregate assuming independence (conservative approach)
        let survival = 1.0;
        fileRisks.forEach(risk => {
            survival *= (1 - risk);
        });

        const globalRaw = 1 - survival;
        return 1 - Math.exp(-this.damping * globalRaw);
    }
}

module.exports = new ScoringEngine();
