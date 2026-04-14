/**
 * Sentinel: Repo Orchestrator
 * Logic for auditing repository security and applying "Sentinel Standard" hardening.
 */

'use strict';

const ghBridge = require('./gh_bridge');
const fs = require('fs');
const path = require('path');

const SENTINEL_STANDARD_PROTECTION = {
    required_status_checks: {
        strict: true,
        contexts: ['Sentinel Static analysis', 'build']
    },
    enforce_admins: true,
    required_pull_request_reviews: {
        dismiss_stale_reviews: true,
        require_code_owner_reviews: false,
        required_approving_review_count: 1
    },
    restrictions: null,
    allow_force_pushes: false,
    allow_deletions: false
};

class Orchestrator {
    /**
     * Performs a full security audit of a repository.
     * Returns a score (0-100) and a breakdown of findings.
     */
    async auditRepo(repoFullName) {
        const metadata = ghBridge.getRepoSecurityMetadata(repoFullName);
        if (!metadata) return { error: 'Could not fetch repo metadata. Check permissions/auth.' };

        const protection = ghBridge.getBranchProtection(repoFullName, metadata.default_branch);
        
        // Scan for sentinel workflows and security docs
        const workflows = ghBridge.listPRs(repoFullName); // Using listPRs as a proxy to check if gh works? No, let's use contents.
        const hasSentinelWorkflow = !!ghBridge.getRemoteFileContent(repoFullName, '.github/workflows/pr-security.yml');
        const hasSecurityMd = !!ghBridge.getRemoteFileContent(repoFullName, 'SECURITY.md');
        const hasCodeOwners = !!ghBridge.getRemoteFileContent(repoFullName, 'CODEOWNERS') || 
                             !!ghBridge.getRemoteFileContent(repoFullName, '.github/CODEOWNERS');

        let score = 0;
        const checks = [
            { id: 'branch_protection', name: 'Branch Protection (Main)', status: !!protection, points: 20 },
            { id: 'secret_scanning', name: 'Secret Scanning', status: metadata.secret_scanning === 'enabled', points: 20 },
            { id: 'dependabot', name: 'Dependabot Security Updates', status: metadata.dependabot === 'enabled', points: 20 },
            { id: 'sentinel_ci', name: 'Sentinel CI Workflow', status: hasSentinelWorkflow, points: 20 },
            { id: 'security_docs', name: 'Security Policy (SECURITY.md)', status: hasSecurityMd || hasCodeOwners, points: 20 }
        ];

        checks.forEach(c => { if (c.status) score += c.points; });

        return {
            repo: repoFullName,
            score,
            grade: this.calculateGrade(score),
            checks,
            metadata: {
                defaultBranch: metadata.default_branch,
                visibility: metadata.visibility
            }
        };
    }

    calculateGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 80) return 'A';
        if (score >= 60) return 'B';
        if (score >= 40) return 'C';
        return 'F';
    }

    /**
     * Prepares a hardening plan (Preview).
     */
    async planHarden(repoFullName) {
        const audit = await this.auditRepo(repoFullName);
        const plan = [];

        if (audit.checks.find(c => c.id === 'secret_scanning' && !c.status)) {
            plan.push({ action: 'ENABLE', target: 'Secret Scanning', impact: 'High: Prevents leaked credentials' });
        }
        if (audit.checks.find(c => c.id === 'dependabot' && !c.status)) {
            plan.push({ action: 'ENABLE', target: 'Dependabot Security Updates', impact: 'High: Automated CVE patching' });
        }
        if (audit.checks.find(c => c.id === 'branch_protection' && !c.status)) {
            plan.push({ action: 'PROTECT', target: `branch: ${audit.metadata.defaultBranch}`, impact: 'Critical: Enforces reviews and CI' });
        }
        if (audit.checks.find(c => c.id === 'sentinel_ci' && !c.status)) {
            plan.push({ action: 'CREATE', target: '.github/workflows/sentinel-audit.yml', impact: 'Medium: Continuous PR scanning' });
        }

        return {
            repo: repoFullName,
            audit,
            plan,
            policyRequired: true
        };
    }

    /**
     * Executes the hardening plan.
     */
    async executeHarden(repoFullName, options = {}) {
        const audit = await this.auditRepo(repoFullName);
        const results = [];

        // 1. Enable Security Features
        const securityUpdate = await ghBridge.updateRepoSecurity(repoFullName, {
            secretScanning: true,
            dependabot: true
        });
        results.push({ step: 'Security Features', success: securityUpdate.success });

        // 2. Protect Default Branch
        const protectionUpdate = await ghBridge.updateBranchProtection(
            repoFullName, 
            audit.metadata.defaultBranch, 
            SENTINEL_STANDARD_PROTECTION
        );
        results.push({ step: 'Branch Protection', success: protectionUpdate.success });

        return { success: results.every(r => r.success), results };
    }
}

module.exports = new Orchestrator();
