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
     * Now includes Trust Modeling (Forensics) and Noise Reduction (Path context).
     */
    calculateFileRisk(alerts, fullPath) {
        if (!alerts || alerts.length === 0) return 0;

        const deduplicated = this._deduplicate(alerts, fullPath);
        const weight = this.getContextWeight(fullPath);
        
        // NOISE REDUCTION: Discount risk for non-critical manifests and test files
        let pathDiscount = 1.0;
        if (fullPath.endsWith('package-lock.json') || fullPath.endsWith('yarn.lock')) pathDiscount = 0.3; // High noise in lockfiles
        if (fullPath.includes('/tests/') || fullPath.includes('/__tests__/')) pathDiscount = 0.5; // Tests are lower risk

        let survivalProbability = 1.0;

        deduplicated.forEach(alert => {
            let p = this.severityMap[alert.severity] || 0.1;
            
            // TRUST MODELING: Adjust risk based on forensic author
            let trustFactor = 1.0;
            if (alert.forensics && alert.forensics.author) {
                const author = alert.forensics.author;
                // Core maintainers (trusted authors)
                if (['javier20dev25', 'Javier Astaroth'].includes(author)) {
                    trustFactor = 0.5; // High trust but never 0
                }
            }

            const isOverridden = CONFIG.SCORING.OVERRIDES.some(o => alert.category === o || (alert.type && alert.type.includes(o)));
            const effectiveWeight = isOverridden ? 1.0 : (weight * pathDiscount * trustFactor);
            
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
     * Phase 5 Calibration: Volume-Dampened Aggregation.
     */
    calculateGlobalScore(fileRisks) {
        if (!fileRisks || fileRisks.length === 0) return 0;
        
        // Volume-Dampened Aggregation: Prevents high-volume repos from 
        // exponentially inflating the score just by having many low-risk files.
        const maxRisk = Math.max(...fileRisks);
        const avgRisk = fileRisks.reduce((sum, val) => sum + val, 0) / fileRisks.length;
        
        // Anchor on the worst file, plus a fraction of the repo's average noise
        const globalRaw = maxRisk + (avgRisk * 0.25); 

        return 1 - Math.exp(-this.damping * globalRaw);
    }
}

module.exports = new ScoringEngine();
