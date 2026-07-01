const CONFIG = require('./config');
const RiskConcentrator = require('../risk/concentration');
const BayesianEngine = require('../evidence/bayesian_engine');

/**
 * Sentinel: Scoring Engine (v6.0 - Oracle Brain)
 */
class ScoringEngine {
    constructor() {
        this.config = CONFIG.SCORING;
        this.weights = this.config.CONTEXT_WEIGHTS;
    }

    /**
     * Calculates the Risk Rank for a single finding.
     */
    computeRankScore(f) {
        // 1. Normalize inputs using Intent Matrix (v4.0)
        let intentCfg = { ...(CONFIG.SCORING.INTENT_MATRIX[f.intent] || { baseSeverity: 0.5, weight: 1.0 }) };
        
        // 2. HARD NEGATIVE MINING: Contextual Intent Attenuation
        const isHardNegative = this._isHardNegative(f._fullPath || f._file || f.file || '');
        if (isHardNegative) {
            intentCfg.weight *= 0.5;
        }

        // 3. Bayesian Posterior Confidence (v6.1 - Hero Mode)
        const confidence = BayesianEngine.calculatePosterior([f], {
            isHardNegative,
            isNewFile: f.isNewInDiff,
            isRootUtility: this._isRootUtility(f._fullPath || f.file || '')
        });

        const severity = (f.riskLevel || f.severity || (intentCfg.baseSeverity * 10)) / 10;
        const exploitability = Math.max(0, Math.min(1, f.exploitability || 0.5));
        
        // 4. Resolve Context
        const contextWeight = this.getContextWeight(f._fullPath || f._file || f.file || '');
        const provenanceWeight = this.provenanceScore(f.provenance || 'HISTORICAL');
        
        // 5. Chain & Novelty Bonuses
        const chainBonus = this.chainBonusScore(f.chainTags || [], f.signals || []);
        
        // 6. Noise & Benignity Discounts
        const benignityDiscount = this.benignityDiscountScore(f.provenance || 'HISTORICAL', f._fullPath || f._file || f.file || '');

        // 7. Final Ranking Formula (v6.1 — Bayesian Aware)
        const base =
            0.20 * severity +
            0.35 * confidence + // Bayesian Confidence dominates decision
            0.15 * exploitability +
            0.10 * provenanceWeight +
            0.15 * chainBonus +
            0.05 * (f.isNewInDiff ? 1.0 : 0.0);

        let adjusted =
            base * contextWeight * intentCfg.weight * (1 - benignityDiscount);

        // SUPPLY CHAIN ESCALATION: Lifecycle scripts are high-risk contexts
        const isLifecycleScript = (f._fullPath || f.file || '').toLowerCase().includes('postinstall') || 
                                 (f._fullPath || f.file || '').toLowerCase().includes('preinstall') ||
                                 (f._fullPath || f.file || '').toLowerCase().includes('install.js');
        if (isLifecycleScript) {
            adjusted *= 2.7; // Aggressive escalation for supply chain vectors
        }

        return Math.max(0, Math.min(1, adjusted)) * 100;
    }

    _isRootUtility(file) {
        const parts = file.replace(/\\/g, '/').split('/');
        const filename = parts[parts.length - 1];
        return ['utils.js', 'helpers.js', 'index.js'].includes(filename) && parts.length < 5;
    }

    provenanceScore(prov) {
        const weights = {
            'SANDBOX_CONFIRMATION': 1.0,
            'RUNTIME_TELEMETRY':    0.9,
            'DIFF_NEW':             0.8,
            'PRODUCTION_FILE':      0.7,
            'BENIGN_NOISE':         0.3,
            'HISTORICAL':           0.5
        };
        return weights[prov] || 0.5;
    }

    _isHardNegative(file) {
        const normalized = file.toLowerCase().replace(/\\/g, '/');
        const patterns = [
            'webpack', 'babel', 'vite', 'compiler', 'minify', 
            'rollup', 'esbuild', 'parcel', 'eslint', 'prettier',
            'postcss', 'autoprefixer', 'terser', 'uglify'
        ];
        return patterns.some(p => normalized.includes(p));
    }

    calculateFileRisk(findings, fullPath) {
        if (!findings || findings.length === 0) return 0;
        const uniqueFindings = new Map();
        findings.forEach(f => {
            const key = `${f.type}:${f.line}`;
            if (!uniqueFindings.has(key) || f.severity > uniqueFindings.get(key).severity) {
                uniqueFindings.set(key, f);
            }
        });
        const ranks = Array.from(uniqueFindings.values()).map(f => this.computeRankScore({
            ...f,
            file: fullPath,
            _fullPath: fullPath
        }));
        return Math.max(...ranks) / 100;
    }

    getContextWeight(fullPath) {
        const parts = fullPath.split(/[\\/]/);
        const filename = parts[parts.length - 1];
        if (this.weights[filename]) return this.weights[filename];
        for (const dir in this.weights) {
            if (parts.includes(dir)) return this.weights[dir];
        }
        return this.weights['default'] || 0.7;
    }

    benignityDiscountScore(provenance, file) {
        const normalized = file.toLowerCase().replace(/\\/g, '/');
        
        // SUPPLY CHAIN SAFETY: Never discount lifecycle scripts
        const isLifecycleScript = normalized.includes('postinstall') || 
                                normalized.includes('preinstall') || 
                                normalized.includes('install.js');
        if (isLifecycleScript) return 0;

        let discount = 0;
        if (provenance === "TEST_FIXTURE") discount += 0.60;
        if (provenance === "DOC_EXAMPLE")  discount += 0.50;
        if (provenance === "GENERATED")    discount += 0.65;
        if (provenance === "BENIGN_NOISE") discount += 0.70;
        if (normalized.includes("/node_modules/")) discount += 0.90;
        if (normalized.includes("/dist/"))         discount += 0.85;
        if (normalized.includes("/build/"))        discount += 0.80;
        if (normalized.includes("/vendor/"))       discount += 0.85;
        if (normalized.includes("/fixtures/"))     discount += 0.75;
        if (normalized.includes("/__tests__/"))    discount += 0.75;
        if (normalized.includes("/test/"))         discount += 0.60;
        if (normalized.includes("/docs/"))         discount += 0.55;
        if (normalized.includes("/examples/"))     discount += 0.50;
        if (normalized.includes("/lib/"))           discount += 0.25;
        if (normalized.includes("/adapters/"))      discount += 0.15;
        if (normalized.includes("/core/"))          discount += 0.15;
        if (normalized.includes("/helpers/"))       discount += 0.15;
        if (normalized.includes("/utils/"))         discount += 0.15;
        if (normalized.includes("/scripts/"))       discount += 0.20; // Reduced from 0.30
        if (normalized.includes(".d.ts"))           discount += 0.45;
        return Math.max(0, Math.min(1, discount));
    }

    chainBonusScore(tags = [], signals = []) {
        let bonus = 0;
        const hasExec = tags.includes("EXECUTION");
        const hasExfil = tags.includes("EXFILTRATION");
        if (hasExec && hasExfil) bonus += 0.15;
        if (signals.length > 3) bonus += 0.05;
        return Math.min(0.20, bonus);
    }

    calculateGlobalScore(fileRisks, mode = 'REPO') {
        const validRisks = (fileRisks || []).filter(r => !isNaN(r));
        if (validRisks.length === 0) return 0;
        const stats = RiskConcentrator.analyze(validRisks);
        const anchorRisk = stats.top1;
        const top3Risk = stats.top3;
        const concentration = stats.concentration;
        const avgRisk = validRisks.reduce((sum, val) => sum + val, 0) / validRisks.length;
        const weights = {
            anchor: 0.40,
            top3: 0.25,
            concentration: 0.20,
            noiseDampening: 0.15
        };
        const gamma = 0.25;
        const globalRaw = weights.anchor * anchorRisk + 
                          weights.top3 * top3Risk + 
                          weights.concentration * concentration + 
                          weights.noiseDampening * (avgRisk * gamma);
        const lambda = mode === "PR" ? 2.5 : mode === "REPO" ? 2.2 : 2.3;
        const dampenedRisk = 1 - Math.exp(-lambda * globalRaw);
        return Math.max(0, Math.min(1, dampenedRisk));
    }
}

module.exports = new ScoringEngine();
