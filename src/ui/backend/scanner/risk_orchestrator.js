/**
 * Sentinel: Risk Orchestrator (v2.9 — Policy Driven)
 * 
 * Aggregates signals into a deterministic verdict using ScoringEngine (v10).
 * v2.9: Integrated with Policy Engine for Governance-as-Code.
 */

'use strict';

const crypto = require('crypto');
const ScoringEngine = require('./scoring_engine');
const PolicyEngine = require('./policy_engine');

const SESSION_CACHE = new Map();
const COOLDOWN_MS = 60000;

const TRUST_LEVELS = {
    AUTHORIZED: 2,
    PARTNER: 1,
    RESTRICTED: 0
};

class RiskOrchestrator {

    static quantizeWithJitter(score, jitterAmount = 0.05, fingerprint = '', user = 'anonymous') {
        const buckets = [0, 0.25, 0.50, 0.75, 1.0];
        let nearest = buckets[0];
        let minDist = Math.abs(score - nearest);
        for (const b of buckets) {
            const dist = Math.abs(score - b);
            if (dist < minDist) {
                minDist = dist;
                nearest = b;
            }
        }
        const hourWindow = Math.floor(Date.now() / (1000 * 60 * 60));
        const seed = `${fingerprint}:${user}:${hourWindow}`;
        const hash = crypto.createHash('sha256').update(seed).digest();
        const rawByte = hash.readUInt8(0);
        const jitter = ((rawByte / 255) * (jitterAmount * 2)) - jitterAmount;
        return Math.max(0, Math.min(1, nearest + jitter));
    }

    static _generateTrace(fingerprint, user) {
        const salt = process.env.SENTINEL_TRACE_SALT || 's3cr3t_s4lt';
        return crypto.createHmac('sha256', salt)
            .update(`${fingerprint}:${user}:${Math.floor(Date.now() / (1000 * 60 * 60))}`)
            .digest('hex').substring(0, 16);
    }

    static _calcProbingStats(fingerprint) {
        if (!fingerprint) return { intensity: 0, delayMs: 0 };
        const now = Date.now();
        const records = (SESSION_CACHE.get(fingerprint) || []).filter(t => now - t < COOLDOWN_MS);
        records.push(now);
        SESSION_CACHE.set(fingerprint, records);
        const count = records.length;
        let delayMs = 0;
        if (count >= 7) delayMs = Math.floor(Math.random() * 5000) + 3000;
        else if (count >= 4) delayMs = Math.floor(Math.random() * 2000) + 1000;
        return { intensity: count, delayMs };
    }

    static getRiskBand(score) {
        const RISK_BANDS = {
            NEGLIGIBLE:       { min: 0.00, max: 0.15, priority: 'P4', action: 'NO_ACTION',                 label: 'Negligible Risk', message: 'No significant threats detected. Safe for deployment.' },
            LOW:              { min: 0.15, max: 0.35, priority: 'P3', action: 'MONITOR',                    label: 'Low Risk', message: 'Minor security anomalies detected. Recommended monitoring.' },
            MODERATE:         { min: 0.35, max: 0.60, priority: 'P2', action: 'REVIEW_RECOMMENDED',         label: 'Moderate Risk', message: 'Behavioral patterns suggest potential risk. Manual review recommended.' },
            HIGH:             { min: 0.60, max: 0.80, priority: 'P1', action: 'INVESTIGATION_REQUIRED',     label: 'High Risk', message: 'Suspicious signals detected in sensitive paths. Investigation required.' },
            HIGH_AGGREGATED:  { min: 0.80, max: 0.95, priority: 'P1', action: 'PATTERN_INVESTIGATION',      label: 'High Aggregated Risk', message: 'Multiple risk factors identified. Chain of execution suggests high threat.' },
            CRITICAL:         { min: 0.95, max: 1.00, priority: 'P0', action: 'IMMEDIATE_REMEDIATION',      label: 'Critical Risk', message: 'Exploitable vulnerability or malicious payload confirmed. Stop deployment.' }
        };
        for (const [name, band] of Object.entries(RISK_BANDS)) {
            if (score >= band.min && score < band.max) return { name, ...band, score };
        }
        return { name: 'CRITICAL', ...RISK_BANDS.CRITICAL, score };
    }

    static arbitrate(signals, profileName = 'balanced', oracleCtx = {}) {
        const { isAuthorized = true, fingerprint = '', user = 'anonymous' } = oracleCtx;
        
        let trustLevel = TRUST_LEVELS.RESTRICTED;
        if (isAuthorized) trustLevel = TRUST_LEVELS.AUTHORIZED;
        else if (user.toLowerCase().includes('partner') || user.toLowerCase().includes('agent')) trustLevel = TRUST_LEVELS.PARTNER;

        const exposure = PolicyEngine.resolveExposure(trustLevel);
        const probing = RiskOrchestrator._calcProbingStats(fingerprint);
        const traceId = RiskOrchestrator._generateTrace(fingerprint, user);

        // LOCKDOWN Check (Anti-Exfiltration)
        if (exposure.isLockdown && probing.intensity > 10) {
            return { decision: 'BLOCK', score: 1.0, riskBand: RiskOrchestrator.getRiskBand(1.0), lockdown: true, traceId };
        }

        if (!signals || signals.length === 0) {
            return { decision: 'PASS', score: 0, riskBand: RiskOrchestrator.getRiskBand(0), traceId, trustLevel, policy: PolicyEngine.getPolicyInfo() };
        }

        const fileRisks = [];
        const fileMap = {};
        for (const s of signals) {
            const file = s._fullPath || s._file || 'unknown';
            if (!fileMap[file]) fileMap[file] = [];
            fileMap[file].push(s);
        }
        for (const file in fileMap) fileRisks.push(ScoringEngine.calculateFileRisk(fileMap[file], file));

        let finalScore = ScoringEngine.calculateGlobalScore(fileRisks);
        if (trustLevel === TRUST_LEVELS.RESTRICTED && probing.intensity > 5) finalScore = Math.min(1.0, finalScore * 1.05);

        const threshold = profileName === 'strict' ? 0.60 : 0.70;
        const decision = finalScore >= threshold ? 'BLOCK' : 'PASS';

        const reportedScore = (exposure.redaction === 'none') 
            ? finalScore 
            : RiskOrchestrator.quantizeWithJitter(finalScore, exposure.jitter, fingerprint, user);

        return {
            decision,
            score: Math.round(reportedScore * 100) / 100,
            riskBand: RiskOrchestrator.getRiskBand(finalScore),
            traceId,
            probingIntensity: probing.intensity,
            delayMs: probing.delayMs,
            trustLevel,
            policy: PolicyEngine.getPolicyInfo(),
            rationale: {
                reason: decision === 'BLOCK' ? 'Aggregated Risk Threshold Exceeded' : 'Risk within acceptable bounds',
                topContributor: RiskOrchestrator._applyPolicyFilter(signals[0], exposure.redaction),
                contributors: signals.slice(0, 3).map(s => RiskOrchestrator._applyPolicyFilter(s, exposure.redaction))
            }
        };
    }

    static _applyPolicyFilter(signal, mode) {
        if (!signal || mode === 'none') return signal;
        
        // Phase 13.5: Tactical Silence Redaction
        const redacted = { 
            severity: signal.severity, 
            riskLevel: signal.riskLevel,
            source: 'sentinel-policy-firewall'
        };

        if (mode === 'balanced') {
            redacted.type = signal.type || 'SUSPICIOUS_BEHAVIOR';
            redacted.category = signal.category || 'POLICY_VIOLATION';
            redacted.description = signal.description || 'Action flagged by security policy.';
            redacted.evidence = '[CONTENT_REDACTED]';
        } else {
            // Aggressive Mode: Absolute intelligence suppression
            redacted.type = 'POLICY_ENFORCEMENT_SIGNAL';
            redacted.description = 'Access to specific threat intelligence is restricted under organizational policy.';
            redacted.evidence = '[REDACTED — Authorized access required]';
        }
        return redacted;
    }
}

module.exports = RiskOrchestrator;
