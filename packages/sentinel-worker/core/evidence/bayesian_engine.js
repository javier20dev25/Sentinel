/**
 * Sentinel: Bayesian Confidence Engine (v6.6 - Sovereignty)
 * 
 * Implements Calibrated Posterior Probability with Temperature Scaling.
 * Features: Orthogonal Killchain Bonuses, Calibrated Priors, and Intent Convergence.
 */

'use strict';

class BayesianEngine {
    constructor() {
        this.evidenceWeights = {
            'INTENT:EXECUTION':              7.0,  // Up-weighted for v6.6
            'INTENT:EXFILTRATION':           7.5,
            'INTENT:NETWORK':                6.5,
            'INTENT:EVASION':                5.5,
            'INTENT:OBFUSCATION':            5.0,
            'INTENT:SUPPLY_CHAIN_TAMPERING': 8.5,
            'INTENT:CI_CD_ABUSE':            6.0,
            'SENSOR:AST':                    1.2,
            'SENSOR:DATAFLOW':               3.0,
            'SENSOR:SANDBOX':                10.0,
            'SENSOR:RUNTIME':                7.5,
            'CONTEXT:NEW_FILE':              2.0,
            'CONTEXT:REPUTATION_ANOMALY':    4.5,  // Critical signal
            'CONTEXT:HARD_NEGATIVE':         -6.0
        };

        this.evidenceFamilies = {
            'EXECUTION': ['EXECUTION', 'DYNAMIC_EXECUTION', 'PROCESS_EXEC', 'SHELL_EXEC'],
            'NETWORK': ['NETWORK', 'NETWORK_CAPABILITY', 'EXFILTRATION', 'COORDINATED_NETWORK_EXFIL'],
            'SECRETS': ['SECRET_ACCESS', 'ENV_ACCESS', 'CREDENTIAL_THEFT'],
            'OBFUSCATION': ['OBFUSCATION', 'OBFUSCATION_CHAIN', 'ENCODING', 'RECONSTRUCTION'],
            'PERSISTENCE': ['PERSISTENCE', 'HOOK_ABUSE', 'SYSTEM_TAMPERING']
        };
    }

    /**
     * Calculates the Calibrated Prior Logit.
     */
    contextualPrior(ctx = {}) {
        let priorLogit = -6.9; // Base P(M) ~ 0.001

        if (ctx.isNewMaintainer) priorLogit += 2.8; 
        if (ctx.isReleaseCandidate) priorLogit += 2.5;
        if (ctx.isLockfileChange) priorLogit += 3.5; 
        if (ctx.isLowReputation) priorLogit += 3.0;

        // Intent Convergence Bonus (Sovereignty Grade)
        if (ctx.convergenceScore) {
            // Nonlinear boost for converging behaviors
            priorLogit += Math.pow(ctx.convergenceScore, 1.5) * 3.0;
        }

        return priorLogit;
    }

    /**
     * Calculates the Calibrated Posterior Confidence.
     */
    calculatePosterior(findings, ctx = {}) {
        let totalLogit = this.contextualPrior(ctx);

        const familyCounts = {};
        const uniqueFamilies = new Set();
        
        findings.forEach(f => {
            const family = this._getFamily(f.intent);
            familyCounts[family] = (familyCounts[family] || 0) + 1;
            uniqueFamilies.add(family);
            
            // Diminishing returns within family (Anti-Inflation)
            const decay = familyCounts[family] === 1 ? 1.0 : (familyCounts[family] === 2 ? 0.3 : 0.05);
            totalLogit += (this.evidenceWeights[`INTENT:${f.intent}`] || 2.5) * decay;
        });

        // KILLCHAIN BONUS: Coordination across 3+ families is nearly always malicious
        if (uniqueFamilies.size >= 4) {
            totalLogit += 6.0; // Critical coordination
        } else if (uniqueFamilies.size === 3) {
            totalLogit += 3.5;
        } else if (uniqueFamilies.size === 2) {
            totalLogit += 1.5;
        }

        // Contextual Signals
        if (ctx.reputationScore > 0.5) totalLogit += this.evidenceWeights['CONTEXT:REPUTATION_ANOMALY'];
        if (ctx.isHardNegative) totalLogit += this.evidenceWeights['CONTEXT:HARD_NEGATIVE'];

        // TEMPERATURE SCALING (v6.6 Calibration)
        // T > 1.0 softens the probability curve to avoid "overconfident" middle scores.
        const T = 1.25; 
        const probability = 1 / (1 + Math.exp(-totalLogit / T));
        
        // Final score calibration (Enterprise Guardrails)
        return Math.max(0.01, Math.min(0.99, probability));
    }

    _getFamily(intent) {
        for (const [family, members] of Object.entries(this.evidenceFamilies)) {
            if (members.includes(intent)) return family;
        }
        return intent;
    }
}

module.exports = new BayesianEngine();
