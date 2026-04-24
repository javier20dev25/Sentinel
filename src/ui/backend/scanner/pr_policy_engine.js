/**
 * Sentinel: PR Policy Engine (Firewall)
 * 
 * Enforces repository-level policies during Pull Requests.
 * Supports path-based rules (strict, advisory, require-review).
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = "1.0";
const POLICY_DIR = '.sentinel';
const POLICY_FILE = 'policies.json';
const POLICY_LOCAL_FILE = 'policies.local.json';

class PRPolicyEngine {
    constructor() {
        this.policies = {
            policy_schema_version: SCHEMA_VERSION,
            rules: []
        };
    }

    /**
     * Initializes the policy directory if it doesn't exist.
     */
    initDir(repoPath) {
        const dirPath = path.join(repoPath, POLICY_DIR);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        return dirPath;
    }

    /**
     * Loads policies from the repository.
     * Merges policies.json (Source of Truth) with policies.local.json (Local overrides).
     */
    loadPolicies(repoPath) {
        const mainPath = path.join(repoPath, POLICY_DIR, POLICY_FILE);
        const localPath = path.join(repoPath, POLICY_DIR, POLICY_LOCAL_FILE);

        let mainPolicies = { policy_schema_version: SCHEMA_VERSION, rules: [] };
        let localPolicies = { rules: [] };

        if (fs.existsSync(mainPath)) {
            try {
                mainPolicies = JSON.parse(fs.readFileSync(mainPath, 'utf8'));
                if (mainPolicies.policy_schema_version !== SCHEMA_VERSION) {
                    console.warn(`[WARNING] Policy schema version mismatch. Expected ${SCHEMA_VERSION}, got ${mainPolicies.policy_schema_version || 'none'}.`);
                }
            } catch (e) {
                console.error('[ERROR] Failed to parse main policies.json:', e.message);
            }
        }

        if (fs.existsSync(localPath)) {
            try {
                localPolicies = JSON.parse(fs.readFileSync(localPath, 'utf8'));
            } catch (e) {
                console.error('[ERROR] Failed to parse local policies.local.json:', e.message);
            }
        }

        // Merge rules (local overrides main if path matches)
        const ruleMap = new Map();
        mainPolicies.rules.forEach(r => ruleMap.set(r.path, r));
        localPolicies.rules.forEach(r => {
            if (r.path) ruleMap.set(r.path, { ...ruleMap.get(r.path), ...r });
        });

        this.policies = {
            policy_schema_version: mainPolicies.policy_schema_version || SCHEMA_VERSION,
            rules: Array.from(ruleMap.values())
        };

        return this.policies;
    }

    /**
     * Saves a rule to the Source of Truth (policies.json).
     */
    saveRule(repoPath, rule) {
        this.initDir(repoPath);
        this.loadPolicies(repoPath);

        const existingIdx = this.policies.rules.findIndex(r => r.path === rule.path);
        if (existingIdx >= 0) {
            this.policies.rules[existingIdx] = rule;
        } else {
            this.policies.rules.push(rule);
        }

        const mainPath = path.join(repoPath, POLICY_DIR, POLICY_FILE);
        fs.writeFileSync(mainPath, JSON.stringify(this.policies, null, 2));
    }

    /**
     * Removes a rule by path from the Source of Truth.
     */
    removeRule(repoPath, targetPath) {
        this.loadPolicies(repoPath);
        const initialCount = this.policies.rules.length;
        this.policies.rules = this.policies.rules.filter(r => r.path !== targetPath);
        
        if (this.policies.rules.length < initialCount) {
            const mainPath = path.join(repoPath, POLICY_DIR, POLICY_FILE);
            fs.writeFileSync(mainPath, JSON.stringify(this.policies, null, 2));
            return true;
        }
        return false;
    }

    /**
     * Evaluates a list of modified files against the loaded policies.
     * 
     * @param {Array<string>} files - List of modified file paths (relative to repo root)
     * @returns {Object} { verdict: 'PASS'|'FAIL'|'ADVISORY', violations: Array }
     */
    evaluateFiles(files) {
        const violations = [];
        let highestSeverity = 'PASS';

        files.forEach(file => {
            this.policies.rules.forEach(rule => {
                if (this.matchPath(file, rule.path)) {
                    const violation = this.checkRule(file, rule);
                    if (violation) {
                        violations.push(violation);
                        if (violation.mode === 'strict') {
                            highestSeverity = 'FAIL';
                        } else if (highestSeverity !== 'FAIL' && violation.mode === 'advisory') {
                            highestSeverity = 'ADVISORY';
                        }
                    }
                }
            });
        });

        return {
            verdict: highestSeverity,
            violations
        };
    }

    /**
     * Helper to match wildcard paths (e.g. src/security/*)
     */
    matchPath(file, rulePath) {
        // Simple wildcard to regex conversion
        const escapeRegex = (s) => s.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
        const regexStr = "^" + escapeRegex(rulePath).replace(/\\\*/g, ".*") + "$";
        const regex = new RegExp(regexStr);
        return regex.test(file);
    }

    /**
     * Checks if a file modification violates a specific rule.
     */
    checkRule(file, rule) {
        // Types: no-modify, require-review
        // Modes: strict, advisory, audit
        
        if (rule.rule === 'no-modify') {
            return {
                file,
                rule: rule.rule,
                pathMatched: rule.path,
                mode: rule.mode || 'strict',
                message: `Modification to protected path '${file}' is prohibited.`
            };
        }

        if (rule.rule === 'require-review') {
            const reviewers = rule.reviewers || 'security-team';
            return {
                file,
                rule: rule.rule,
                pathMatched: rule.path,
                mode: rule.mode || 'strict',
                message: `Modification to '${file}' requires approval from: ${reviewers}.`
            };
        }

        return null;
    }
}

module.exports = new PRPolicyEngine();
