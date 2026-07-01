/**
 * Sentinel: Policy Engine (v2.0 — Dual Enforcement)
 * 
 * Manages institutional governance policies for risk intelligence exposure.
 * 
 * v2.0: Adds enforcement_mode (strict vs advisory) to prevent Sentinel
 *       from becoming "the tool devs disable because it blocks everything."
 * 
 * Strict mode:  CI/CD pipelines — hard blocks, exit code 1
 * Advisory mode: Local dev — warnings, education, never blocks
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_POLICY = {
    name: 'Standard Organizational Policy',
    exposure_level: 'restricted',
    redaction_mode: 'aggressive',
    enforcement_mode: 'canary',    // 'strict' | 'advisory' | 'canary'
    canary_whitelist: [
        'sentinel-canary-test', 
        'facebook/react',        // High-Value Frontend
        'expressjs/express',     // Infrastructure Core
        'lodash/lodash'          // Low-Noise Library
    ],
    audit: {
        enabled: true,
        traceability: 'high',
        leak_response: 'traceable'
    },
    governance: {
        enforce_authorized_only: true,
        allow_partner_metadata: true,
        intelligence_opt_in: false,       // REQUIRES EXPLICIT CONSENT via UI/CLI
        data_sharing_level: 1             // 1: Aggregated/Tags, 2: Tokenized, 3: Full Payload (Enterprise Only)
    },
    install_policy: {
        block_unpinned_docker: true,
        require_digest: false,          // future: when true, blocks all un-digested pulls
        max_typosquat_distance: 2,
        sandbox_on_suspicious: true
    }
};

class PolicyEngine {
    constructor() {
        this.activePolicy = { ...DEFAULT_POLICY };
        this._loadLocalPolicy();
        this._loadCanaryTargets();
    }

    _loadCanaryTargets() {
        const configPath = path.join(__dirname, '..', '..', '..', 'config', 'canary_targets.json');
        if (fs.existsSync(configPath)) {
            try {
                const targets = JSON.parse(fs.readFileSync(configPath, 'utf8'));
                this.activePolicy.canary_whitelist = targets.canary_whitelist.map(t => t.id);
                this.activePolicy.canary_metadata = targets.canary_whitelist;
            } catch (e) {
                console.warn('[PolicyEngine] Failed to load canary_targets.json, falling back to default.');
            }
        }
    }

    _loadLocalPolicy() {
        const configPath = path.join(os.homedir(), '.sentinel', 'sentinel-policy.json');
        if (fs.existsSync(configPath)) {
            try {
                const userPolicy = JSON.parse(fs.readFileSync(configPath, 'utf8'));
                // Deep merge
                this.activePolicy = this._deepMerge(DEFAULT_POLICY, userPolicy);
            } catch (e) {
                // Fail-closed: bad policy = use defaults
            }
        }

        // CI/CD auto-detection: force strict mode ONLY if currently advisory and in CI
        const isCI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true' || !process.stdout.isTTY;
        if (isCI && this.activePolicy.enforcement_mode === 'advisory') {
            this.activePolicy.enforcement_mode = 'strict';
        }
    }

    _deepMerge(target, source) {
        const result = { ...target };
        for (const key of Object.keys(source)) {
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                result[key] = this._deepMerge(target[key] || {}, source[key]);
            } else {
                result[key] = source[key];
            }
        }
        return result;
    }

    /** Is this a hard-block environment or advisory-only? */
    isStrictMode() {
        return this.activePolicy.enforcement_mode === 'strict';
    }

    /** Should we actually exit(1) on a BLOCK verdict? */
    shouldEnforceBlock(repoId = '') {
        const mode = this.activePolicy.enforcement_mode;
        const whitelist = this.activePolicy.canary_whitelist || [];
        const isMatched = whitelist.includes(repoId);
        
        let decision = false;
        let reason = 'NONE';

        if (mode === 'strict') {
            decision = true;
            reason = 'POLICY_STRICT_GLOBAL';
        } else if (mode === 'advisory') {
            decision = false;
            reason = 'POLICY_ADVISORY_GLOBAL';
        } else if (mode === 'canary') {
            decision = isMatched;
            reason = isMatched ? 'CANARY_WHITELIST_MATCH' : 'SHADOW_MODE_NO_MATCH';
        }

        return {
            enforce: decision,
            policy_mode: mode,
            canary_match_reason: reason,
            policy_version: 'v8.4.0-gold'
        };
    }

    /** Resolves the required exposure context based on current trust level. */
    resolveExposure(trustLevel) {
        const policy = this.activePolicy;

        if (trustLevel === 2) return { redaction: 'none', jitter: 0, audit: policy.audit.enabled };
        if (trustLevel === 1) {
            return {
                redaction: policy.redaction_mode === 'aggressive' ? 'high' : 'balanced',
                jitter: 0.02, audit: true
            };
        }
        return {
            redaction: 'aggressive', jitter: 0.05, audit: true,
            isLockdown: policy.audit.leak_response === 'lockdown'
        };
    }

    getPolicyInfo() {
        return {
            name: this.activePolicy.name,
            exposure: this.activePolicy.exposure_level,
            enforcement: this.activePolicy.enforcement_mode,
            auditStatus: this.activePolicy.audit.enabled ? 'ENABLED' : 'DISABLED'
        };
    }
}

module.exports = new PolicyEngine();
