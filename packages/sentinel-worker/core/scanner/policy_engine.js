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
    enforcement_mode: 'strict',    // 'strict' | 'advisory'
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

        // CI/CD auto-detection: strict mode in non-interactive environments
        if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true' || !process.stdout.isTTY) {
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
    shouldEnforceBlock() {
        return this.isStrictMode();
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
