/**
 * Sentinel: Repository Taxonomy & Tolerance Profiles (v2.0 - Scoring-Integrated)
 * 
 * Defines risk tolerance levels based on repository purpose.
 * These profiles affect SCORING, not just logging.
 * 
 * Each profile defines:
 *   - Tolerance: how much to dampen specific signal classes (Stage 1)
 *   - Confidence scaling: profile-specific confidence adjustment (Stage 7)
 *   - Verdict thresholds: profile-specific score→verdict boundaries
 *   - Expected signals: signals that are normal for this repo class
 */

const REPO_PROFILES = {
    infrastructure: {
        executionTolerance: 0.9,
        networkTolerance: 0.9,
        encodingTolerance: 0.8,
        // Confidence scaling: infra repos have higher false-positive rates,
        // so we reduce confidence for ambiguous signals
        confidenceScale: 0.85,
        // Verdict thresholds: infrastructure needs HIGHER scores to trigger
        verdictThresholds: { REVIEW: 50, REVIEW_HIGH_SIGNAL: 75, SECURITY_HOLD: 85, BLOCK: 95 },
        // Signals expected in normal operation (not inherently suspicious)
        expectedSignals: ['NETWORK', 'EXECUTION', 'ENCODING', 'SYSTEM_ACCESS'],
        // Convergence boost: smaller for infra (networking patterns are normal)
        convergenceBoost: 15,
        description: 'Servers, Proxies, Build Engines'
    },
    frontend: {
        executionTolerance: 0.4,
        networkTolerance: 0.5,
        encodingTolerance: 0.4,
        confidenceScale: 1.1,
        verdictThresholds: { REVIEW: 35, REVIEW_HIGH_SIGNAL: 60, SECURITY_HOLD: 75, BLOCK: 90 },
        expectedSignals: ['NETWORK'],
        convergenceBoost: 45,
        description: 'React/Vue/Next Apps'
    },
    cli_tools: {
        executionTolerance: 0.8,
        networkTolerance: 0.6,
        encodingTolerance: 0.7,
        confidenceScale: 0.95,
        verdictThresholds: { REVIEW: 45, REVIEW_HIGH_SIGNAL: 70, SECURITY_HOLD: 80, BLOCK: 92 },
        expectedSignals: ['EXECUTION'],
        convergenceBoost: 30,
        description: 'Bundlers, Linters, CLI Utilities'
    },
    libraries: {
        executionTolerance: 0.6,
        networkTolerance: 0.5,
        encodingTolerance: 0.6,
        confidenceScale: 1.0,
        verdictThresholds: { REVIEW: 40, REVIEW_HIGH_SIGNAL: 65, SECURITY_HOLD: 78, BLOCK: 90 },
        expectedSignals: [],
        convergenceBoost: 40,
        description: 'Utility libs (Lodash, Zod, etc.)'
    },
    default: {
        executionTolerance: 0.7,
        networkTolerance: 0.6,
        encodingTolerance: 0.6,
        confidenceScale: 1.0,
        verdictThresholds: { REVIEW: 40, REVIEW_HIGH_SIGNAL: 65, SECURITY_HOLD: 75, BLOCK: 90 },
        expectedSignals: [],
        convergenceBoost: 40,
        description: 'Standard Application Code'
    }
};

// Known repositories
const REPO_MAP = {
    'expressjs/express': 'infrastructure',
    'nodejs/node': 'infrastructure',
    'nginx/nginx': 'infrastructure',
    'vitejs/vite': 'infrastructure',
    'facebook/react': 'frontend',
    'vercel/next.js': 'frontend',
    'vuejs/vue': 'frontend',
    'lodash/lodash': 'libraries',
    'colinhacks/zod': 'libraries',
    'axios/axios': 'libraries'
};

function getProfile(repoNameOrType) {
    let type = REPO_MAP[repoNameOrType];
    
    // Allow direct lookup by type name (useful for testing/overrides)
    if (!type && REPO_PROFILES[repoNameOrType]) {
        type = repoNameOrType;
    }
    
    if (!type) {
        type = 'default';
    }

    return {
        type,
        ...REPO_PROFILES[type]
    };
}

/**
 * Returns true if the signal intent is expected for this profile.
 * Used to reduce confidence for signals that are normal in this context.
 */
function isExpectedSignal(profileType, intent) {
    const profile = REPO_PROFILES[profileType] || REPO_PROFILES.default;
    return profile.expectedSignals.includes(intent);
}

module.exports = {
    REPO_PROFILES,
    getProfile,
    isExpectedSignal
};
