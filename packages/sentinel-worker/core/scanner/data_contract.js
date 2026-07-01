/**
 * Sentinel: Canonical Data Contract (v8.0.3 - Frozen)
 * 
 * Single source of truth for all output schemas.
 * Every external-facing result MUST pass through this normalizer.
 * Internal pipeline fields are stripped; only contract fields survive.
 * 
 * RULE: rawImpact = pre-policy score. effectiveImpact = post-dampeners.
 *       verdict = final decision. reasoningTrace = reproducible explanation.
 */

'use strict';

const crypto = require('crypto');

const CALIBRATION_VERSION = 'v8.4.0';

const VERDICT_ENUM = Object.freeze([
    'PASS',
    'REVIEW',
    'REVIEW_HIGH_SIGNAL',
    'SECURITY_HOLD',
    'BLOCK'
]);

/**
 * Normalizes internal pipeline output into the frozen external contract.
 * Strips internal-only fields. Adds calibration metadata.
 * 
 * @param {object} pipelineResult - Raw output from RiskOrchestrator.arbitrate()
 * @param {object} meta - { repoId, repoProfile, scanId, file, author }
 * @returns {object} Frozen canonical output
 */
function normalize(pipelineResult, meta = {}) {
    const trace = pipelineResult.reasoningTrace || {};
    const stages = trace.stages || {};

    return Object.freeze({
        // --- IDENTITY ---
        scanId: meta.scanId || null,
        traceId: pipelineResult.traceId || null,
        fingerprint: pipelineResult.fingerprint || null,
        calibrationVersion: CALIBRATION_VERSION,

        // --- THREE CANONICAL OUTPUTS ---
        rawImpact: _clamp(stages.contextualRisk || stages.baseGlobalRisk || 0, 0, 100),
        effectiveImpact: _clamp(pipelineResult.impactScore || 0, 0, 100),
        decisionConfidence: _clamp(pipelineResult.decisionConfidence || 0, 0, 1.0),
        verdict: _validateVerdict(pipelineResult.verdict),

        // --- CONTEXT ---
        repoProfile: meta.repoProfile || 'default',
        repoId: meta.repoId || 'unknown',

        // --- FORENSIC TRACE (reproducible) ---
        reasoningTrace: _sanitizeTrace(trace),

        // --- EVIDENCE ---
        evidenceGraph: pipelineResult.evidenceGraph || [],
        rationale: pipelineResult.rationale || {},

        // --- OPERATIONAL ---
        latencyMs: (pipelineResult.metrics || {}).latency_ms || null
    });
}

/**
 * Normalizes a telemetry record for JSONL logging.
 * Strict schema: no ad-hoc fields leak into logs.
 */
function toObservationRecord(canonicalResult, eventMeta = {}) {
    // Build deterministic audit hash for reproducibility
    const auditInput = `${canonicalResult.scanId}|${canonicalResult.repoId}|${eventMeta.file || ''}|${canonicalResult.effectiveImpact}|${canonicalResult.verdict}|${canonicalResult.calibrationVersion}`;
    const decisionHash = crypto.createHash('sha256').update(auditInput).digest('hex').substring(0, 12);

    return {
        timestamp: new Date().toISOString(),
        event_id: eventMeta.eventId || null,
        repo: canonicalResult.repoId,
        pr: eventMeta.pr || null,
        file: eventMeta.file || null,
        author: eventMeta.author || 'unknown',
        // Canonical triple
        raw_impact: canonicalResult.rawImpact,
        effective_impact: canonicalResult.effectiveImpact,
        confidence: canonicalResult.decisionConfidence,
        verdict: canonicalResult.verdict,
        fingerprint: canonicalResult.fingerprint,
        calibration_version: canonicalResult.calibrationVersion,
        repo_profile: canonicalResult.repoProfile,
        // Audit
        decision_hash: decisionHash,
        // Trace (only for detections, null for observations)
        reasoning: eventMeta.includeTrace ? canonicalResult.reasoningTrace : undefined,
        rationale: eventMeta.includeTrace ? canonicalResult.rationale : undefined,
        latency_ms: canonicalResult.latencyMs
    };
}

/**
 * Schema for versioned human labels.
 */
function toLabelRecord(repoId, fingerprint, labelType, reviewerMeta = {}) {
    if (!['FALSE_POSITIVE', 'TRUE_POSITIVE', 'NEEDS_REVIEW'].includes(labelType)) {
        throw new Error(`Invalid label type: ${labelType}`);
    }
    return {
        timestamp: new Date().toISOString(),
        repoId,
        fingerprint,
        label: labelType,
        reviewer: reviewerMeta.reviewer || 'anonymous',
        reason: reviewerMeta.reason || '',
        repoProfile: reviewerMeta.repoProfile || 'unknown',
        calibrationVersion: CALIBRATION_VERSION,
        labelSetVersion: reviewerMeta.labelSetVersion || 'labels_v1'
    };
}

// --- INTERNAL HELPERS ---

function _clamp(val, min, max) {
    const n = Number(val) || 0;
    return Math.round(Math.max(min, Math.min(max, n)) * 100) / 100;
}

function _validateVerdict(v) {
    return VERDICT_ENUM.includes(v) ? v : 'PASS';
}

function _sanitizeTrace(trace) {
    if (!trace || !trace.stages) return {};
    return {
        stages: trace.stages,
        signals: trace.signals || [],
        dampeners: trace.dampeners || [],
        filters: trace.filters || [],
        pathMultiplier: trace.pathMultiplier || 1.0,
        confidence: trace.confidence || 0
    };
}

module.exports = {
    CALIBRATION_VERSION,
    VERDICT_ENUM,
    normalize,
    toObservationRecord,
    toLabelRecord
};
