'use strict';

/**
 * EngineResult — canonical contract for engine comparison.
 *
 * Every engine (baseline, experimental, future) produces this shape.
 * The comparator only knows EngineResult, not individual engines.
 *
 * @typedef {Object} EngineResult
 * @property {string} engineName         — 'baseline' | 'experimental' | custom
 * @property {string} engineVersion      — semver or build tag
 * @property {string[]} layers           — pipeline layer IDs executed
 * @property {number} timestamp          — Date.now() when result was produced
 * @property {string} scanId             — unique scan identifier (traceId upstream)
 *
 * @property {EngineFinding[]} findings   — normalized findings array
 * @property {number} riskScore          — 0.0–1.0
 * @property {string} verdict            — 'PASS' | 'REVIEW' | 'BLOCK'
 * @property {string} riskBand           — 'NEGLIGIBLE'|'LOW'|'MODERATE'|'HIGH'|'CRITICAL'
 * @property {number} decisionConfidence — 0.0–1.0
 *
 * @property {Object} [evidenceGraph]    — property_graph or evidence_graph output
 * @property {string[]} capabilities     — capability labels extracted
 * @property {Object} [irSummary]        — IR analysis details (experimental)
 * @property {Object} [taxonomyMatches]  — taxonomy technique IDs and counts
 *
 * @property {EngineStats} statistics
 * @property {Object} [metadata]         — engine-specific extended data
 */

/**
 * @typedef {Object} EngineFinding
 * @property {string} id                — unique finding ID
 * @property {string} type              — finding type/classification
 * @property {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'} severity
 * @property {number} riskLevel         — 0–10
 * @property {string} message           — human-readable description
 * @property {string} [file]            — source file path
 * @property {number} [line]            — source line number
 * @property {string} [snippet]         — relevant code snippet
 * @property {string} [sourceEngine]    — 'REGEX'|'AST'|'HEURISTIC'|'IR'|etc
 * @property {string} [techniqueId]     — taxonomy technique identifier
 * @property {string} [capability]      — capability type
 * @property {'high'|'medium'|'low'} [confidence] — signal confidence
 */

/**
 * @typedef {Object} EngineStats
 * @property {number} analysisTimeMs
 * @property {number} memoryBytes
 * @property {number} filesAnalyzed
 * @property {number} filesWithFindings
 * @property {number} totalFindings
 * @property {number} [layersExecuted]
 * @property {number} [symbolsResolved]
 * @property {number} [stringsDecoded]
 */

const VERDICTS = ['PASS', 'REVIEW', 'BLOCK'];
const RISK_BANDS = ['NEGLIGIBLE', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

let scanCounter = 0;

function nextScanId() {
  scanCounter++;
  return `scan_${Date.now()}_${scanCounter}`;
}

function normalizeVerdict(raw) {
  if (VERDICTS.includes(raw)) return raw;
  if (raw === 'REVIEW_HIGH_SIGNAL' || raw === 'SECURITY_HOLD') return 'REVIEW';
  if (raw === true || raw === 1 || raw === '1' || raw === 'BLOCK') return 'BLOCK';
  return 'PASS';
}

function normalizeRiskBand(raw) {
  if (RISK_BANDS.includes(raw)) return raw;
  const upper = String(raw).toUpperCase();
  if (upper.includes('CRIT')) return 'CRITICAL';
  if (upper.includes('HIGH')) return 'HIGH';
  if (upper.includes('MOD') || upper.includes('MED')) return 'MODERATE';
  if (upper.includes('LOW')) return 'LOW';
  if (upper.includes('NEG')) return 'NEGLIGIBLE';
  return 'MODERATE';
}

function normalizeSeverity(raw) {
  if (SEVERITIES.includes(raw)) return raw;
  const upper = String(raw).toUpperCase();
  if (upper === 'CRITICAL' || upper === 'CRIT') return 'CRITICAL';
  if (upper === 'HIGH') return 'HIGH';
  if (upper === 'MEDIUM' || upper === 'MED') return 'MEDIUM';
  if (upper === 'LOW') return 'LOW';
  return 'INFO';
}

/**
 * Create a normalized and frozen EngineResult.
 *
 * @param {Object} opts
 * @param {string} [opts.engineName='custom']
 * @param {string} [opts.engineVersion='0.0.0']
 * @param {string[]} [opts.layers=[]]
 * @param {Object[]} [opts.findings=[]]
 * @param {number} [opts.riskScore=0]
 * @param {string} [opts.verdict='PASS']
 * @param {string} [opts.riskBand='NEGLIGIBLE']
 * @param {number} [opts.decisionConfidence=1.0]
 * @param {Object} [opts.evidenceGraph]
 * @param {string[]} [opts.capabilities=[]]
 * @param {Object} [opts.irSummary]
 * @param {Object} [opts.taxonomyMatches]
 * @param {Object} [opts.statistics={}]
 * @param {Object} [opts.metadata]
 * @returns {EngineResult}
 */
function createEngineResult(opts = {}) {
  const findings = (opts.findings || []).map((f, i) => ({
    id: f.id || `${opts.engineName || 'eng'}_${i}`,
    type: f.type || 'generic',
    severity: normalizeSeverity(f.severity || 'INFO'),
    riskLevel: typeof f.riskLevel === 'number' ? f.riskLevel : f.riskScore || 0,
    message: f.message || f.description || f.title || '',
    file: f.file || f._file || undefined,
    line: f.line || f.line_number || undefined,
    snippet: f.snippet || f.evidence || undefined,
    sourceEngine: f.sourceEngine || f.source_engine || opts.engineName || 'unknown',
    techniqueId: f.techniqueId || undefined,
    capability: f.capability || undefined,
    confidence: f.confidence || undefined,
  }));

  const verdict = normalizeVerdict(opts.verdict);
  const riskScore = Math.min(1, Math.max(0, typeof opts.riskScore === 'number' ? opts.riskScore : 0));

  const stats = {
    analysisTimeMs: opts.statistics?.analysisTimeMs || 0,
    memoryBytes: opts.statistics?.memoryBytes || 0,
    filesAnalyzed: opts.statistics?.filesAnalyzed || 1,
    filesWithFindings: opts.statistics?.filesWithFindings || (findings.length > 0 ? 1 : 0),
    totalFindings: findings.length,
    layersExecuted: opts.statistics?.layersExecuted || opts.layers?.length || 0,
    symbolsResolved: opts.statistics?.symbolsResolved || 0,
    stringsDecoded: opts.statistics?.stringsDecoded || 0,
  };

  const capabilities = opts.capabilities || [];
  const dedupedCaps = [...new Set(capabilities)];

  const result = {
    engineName: opts.engineName || 'custom',
    engineVersion: opts.engineVersion || '0.0.0',
    layers: opts.layers || [],
    timestamp: Date.now(),
    scanId: opts.scanId || nextScanId(),

    findings,
    riskScore,
    verdict,
    riskBand: normalizeRiskBand(opts.riskBand || 'NEGLIGIBLE'),
    decisionConfidence: Math.min(1, Math.max(0, opts.decisionConfidence || 1.0)),

    evidenceGraph: opts.evidenceGraph || undefined,
    capabilities: dedupedCaps,
    irSummary: opts.irSummary || undefined,
    taxonomyMatches: opts.taxonomyMatches || undefined,

    statistics: stats,
    metadata: opts.metadata || undefined,
  };

  return Object.freeze(result);
}

/**
 * In-place mutable variant for building incrementally.
 */
function createMutableEngineResult(opts = {}) {
  const frozen = createEngineResult(opts);
  return JSON.parse(JSON.stringify(frozen));
}

module.exports = {
  createEngineResult,
  createMutableEngineResult,
  normalizeVerdict,
  normalizeSeverity,
  normalizeRiskBand,
  VERDICTS,
  RISK_BANDS,
  SEVERITIES,
};
