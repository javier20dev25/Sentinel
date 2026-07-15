'use strict';

/**
 * Experimental Adapter — wraps the new evasion detector (normalizer + IR +
 * property_graph + legacy layers) into the canonical EngineResult contract.
 *
 * Two modes:
 *   - code mode:   runs assessCode() on actual source code
 *   - source mode: runs normalizer + property_graph on available AST data
 */

const { assessCode } = require('../scanner/evasion/detector');
const { createMutableEngineResult } = require('../contracts/engine_result');

const LAYERS = ['normalize', 'ir_analysis', 'property_graph', 'legacy_patterns', 'legacy_heuristics', 'legacy_semantic', 'legacy_signatures'];

// ── Dead branch removal from source (pre-process for legacy layers) ──

let acorn, walk;
try {
  acorn = require('acorn');
  walk = require('acorn-walk');
} catch (e) {
  acorn = null;
  walk = null;
}

function tryFoldBoolean(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'boolean') return node.value;
  if (node.type === 'UnaryExpression' && node.operator === '!') {
    const arg = tryFoldBoolean(node.argument);
    if (typeof arg === 'boolean') return !arg;
  }
  if (node.type === 'BinaryExpression') {
    const l = node.left, r = node.right;
    if (['===', '!==', '==', '!='].includes(node.operator)) {
      if (l.type === 'Literal' && r.type === 'Literal' && typeof l.value === typeof r.value) {
        const eq = l.value === r.value;
        if (node.operator === '===' || node.operator === '==') return eq;
        if (node.operator === '!==' || node.operator === '!=') return !eq;
      }
    }
  }
  return null;
}

function collectDeadBranches(ast) {
  const dead = [];
  if (!walk) return dead;
  walk.simple(ast, {
    IfStatement(node) {
      const tv = tryFoldBoolean(node.test);
      if (tv === null) return;
      if (tv === false) {
        dead.push({ start: node.consequent.start, end: node.consequent.end });
      } else if (tv === true && node.alternate) {
        dead.push({ start: node.alternate.start, end: node.alternate.end });
      }
    },
    ConditionalExpression(node) {
      const tv = tryFoldBoolean(node.test);
      if (tv === null) return;
      if (tv === false && node.consequent) {
        dead.push({ start: node.consequent.start, end: node.consequent.end });
      } else if (tv === true && node.alternate) {
        dead.push({ start: node.alternate.start, end: node.alternate.end });
      }
    },
    LogicalExpression(node) {
      if (node.operator === '&&') {
        const lv = tryFoldBoolean(node.left);
        if (lv === false) dead.push({ start: node.right.start, end: node.right.end });
      } else if (node.operator === '||') {
        const lv = tryFoldBoolean(node.left);
        if (lv === true) dead.push({ start: node.right.start, end: node.right.end });
      }
    },
  });
  return dead;
}

function stripDeadCode(code) {
  if (!acorn) return code;
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
  } catch (_) {
    try { ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'script' }); } catch (_) { return code; }
  }
  const dead = collectDeadBranches(ast);
  if (dead.length === 0) return code;
  dead.sort((a, b) => b.start - a.start);
  let result = code;
  for (const r of dead) {
    const snippet = result.slice(r.start, r.end);
    const lineCount = snippet.split('\n').length - 1;
    const replacement = lineCount > 0 ? '\n'.repeat(lineCount) : ' ';
    result = result.slice(0, r.start) + replacement + result.slice(r.end);
  }
  return result;
}

/**
 * Run the experimental engine on source code.
 *
 * @param {string} code        — JavaScript source code to analyze
 * @param {Object} [sourceInfo] — metadata about the source (repo, pr, file)
 * @param {Object} [options]
 * @returns {EngineResult}
 */
function produceFromCode(code, sourceInfo = {}, options = {}) {
  const startTime = Date.now();
  const startMemory = process.memoryUsage ? process.memoryUsage().heapUsed : 0;

  // Pre-process: strip dead code branches so ALL layers (including legacy) skip unreachable code
  const cleanedCode = code && code.length > 0 ? stripDeadCode(code) : code;

  const result = assessCode(cleanedCode, sourceInfo.filename || 'unknown.js', options);

  const latencyMs = Date.now() - startTime;
  const memoryBytes = process.memoryUsage ? process.memoryUsage().heapUsed - startMemory : 0;

  const findings = result.findings || [];
  const summary = result.summary || {};

  // Normalize internal capability names to canonical GT names
  const CAP_ALIASES = {
    'prompt_attack': 'prompt_injection',
    'execution': 'execution',
    'Execution': 'execution',
    'obfuscation': 'obfuscation',
    'supply_chain': 'supply_chain',
    'DynamicCodeExecution': 'dynamic_code',
    'Decode': 'decode',
    'NetworkAccess': 'network',
    'ModuleImport': 'module_import',
    'SandboxEscape': 'sandbox_escape',
    'ReflectionAccess': 'reflection',
    'DelayedExecution': 'delayed_execution',
    'EnvironmentAccess': 'env_access',
    'FilesystemWrite': 'filesystem_write',
    'FilesystemRead': 'filesystem_read',
    'GlobalAccess': 'global_access',
    'ProxyWrapping': 'proxy_wrapping',
    'OSCapability': 'os_capability',
    'Parse': 'parse',
  };
  function normalizeCap(cap) { return CAP_ALIASES[cap] || cap; }

  // Extract capabilities from the property graph
  let capabilities = [];
  let propertyGraphJSON = null;
  if (result.propertyGraph && result.propertyGraph.stats) {
    capabilities = (result.propertyGraph.stats.capabilities || []).map(normalizeCap);
    propertyGraphJSON = result.propertyGraph;
  } else {
    const uniqueCaps = [...new Set(findings.map(f => normalizeCap(f.category || f.type)))];
    capabilities = uniqueCaps;
  }

  // Map verdict: DETECTOR verdict → ENGINE verdict
  const verdictMap = {
    'CRITICAL': 'BLOCK',
    'SUSPICIOUS': 'REVIEW',
    'WARNING': 'REVIEW',
    'INFO': 'PASS',
    'CLEAN': 'PASS',
  };
  const rawVerdict = verdictMap[result.verdict] || 'PASS';

  // Map severity to risk score (0-1)
  const severityScoreMap = {
    'CRITICAL': 0.95,
    'HIGH': 0.75,
    'MEDIUM': 0.5,
    'LOW': 0.25,
    'INFO': 0.05,
  };

  const confidenceWeight = { high: 1.0, medium: 0.6, low: 0.2 };

  // Per-finding confidence based on evidence depth and execution context
  const pg = result.propertyGraph;
  const pgNodeCount = pg?.stats?.totalNodes || 0;
  const pgEdgeCount = pg?.stats?.totalEdges || 0;
  const hasGraph = pg && pg.nodes && pg.nodes.length > 0;

  const hasExecutionChain = (f) => {
    if (!hasGraph) return false;
    const capability = f.category;
    if (!capability) return false;
    const capNodes = pg.nodes.filter(n => n.capabilities && n.capabilities.includes(capability));
    if (capNodes.length === 0) return false;
    // Check if any capability node has incoming edges (connected to something)
    const edgeTargets = new Set(pg.edges.map(e => e.target));
    return capNodes.some(n => edgeTargets.has(n.id));
  };

  const isOnlyFindingForCategory = (f, idx, allF) => {
    const cap = f.category;
    return allF.filter(x => x.category === cap).length <= 1;
  };

  const computeConfidence = (f, idx, allF) => {
    // IR-confirmed findings with full evidence graph → high
    if (f.source === 'IR' && hasExecutionChain(f)) return 'high';
    if (f.id && f.id.startsWith('IR-') && pgNodeCount > 3) return 'high';

    // Prompt injection patterns are self-contained attacks — the text IS the payload
    if (f.category === 'prompt_attack') return 'high';

    // EVASION pattern matches are low unless confirmed by multiple signals
    if (f.id && (f.id.startsWith('EVASION-') || f.type?.startsWith('evasion'))) {
      if (hasExecutionChain(f) && !isOnlyFindingForCategory(f, idx, allF)) return 'medium';
      if (f.source === 'IR') return 'medium';
      // CRITICAL severity with corroborating findings → medium
      if (f.severity === 'CRITICAL' && allF.length >= 2) return 'medium';
      return 'low';
    }

    // Property-graph or signature confirmed → medium
    if (hasExecutionChain(f)) return 'medium';
    if (f.source === 'legacy_signatures' || f.source === 'property_graph') return 'medium';

    // SEM and SIG patterns with execution context → medium
    if (f.id && (f.id.startsWith('SEM-') || f.id.startsWith('SIG-'))) {
      if (hasExecutionChain(f) || pgNodeCount > 2) return 'medium';
      // CRITICAL severity with corroborating findings → medium
      if (f.severity === 'CRITICAL' && allF.length >= 2) return 'medium';
      return 'low';
    }

    return 'medium';
  };

  // Annotate findings with confidence and compute aggregate
  const annotatedFindings = findings.map((f, i) => {
    const confidence = computeConfidence(f, i, findings);
    return { ...f, confidence };
  });

  // Compute aggregate risk score with confidence weighting
  let riskScore = 0;
  const confValues = annotatedFindings.map(f => confidenceWeight[f.confidence] || 0.5);
  if (annotatedFindings.length > 0) {
    const maxSeverity = Math.max(...annotatedFindings.map(f => severityScoreMap[f.severity] || 0));
    const countScore = Math.min(1, annotatedFindings.length / 10);
    const avgConf = confValues.reduce((a, b) => a + b, 0) / confValues.length;
    riskScore = Math.max(maxSeverity * avgConf, countScore * 0.3 * avgConf);
  }

  // Calibrate verdict based on highest confidence
  const confLevels = new Set(annotatedFindings.map(f => f.confidence));
  let verdict = rawVerdict;
  let maxConfidence = 'high';
  if (confLevels.has('high')) maxConfidence = 'high';
  else if (confLevels.has('medium')) maxConfidence = 'medium';
  else if (confLevels.has('low')) maxConfidence = 'low';

  // Cap: no findings → always PASS
  if (annotatedFindings.length === 0) verdict = 'PASS';

  // Multi-signal escalation: ≥2 findings with CRITICAL verdict → boost to medium confidence
  if (annotatedFindings.length >= 2 && verdict === 'BLOCK' && maxConfidence === 'low') {
    maxConfidence = 'medium';
  }

  // Cap: low confidence findings can never escalate to BLOCK
  if (maxConfidence === 'low' && verdict === 'BLOCK') verdict = 'REVIEW';

  // Build irSummary and taxonomyMatches from findings
  const irFindings = annotatedFindings.filter(f => f.source === 'IR' || f.id?.startsWith('IR-'));
  const irSummary = {};
  for (const irf of irFindings) {
    const key = irf.id || irf.type;
    irSummary[key] = (irSummary[key] || 0) + 1;
  }

  const taxonomyMatches = {};
  for (const f of annotatedFindings) {
    if (f.id) {
      taxonomyMatches[f.id] = (taxonomyMatches[f.id] || 0) + 1;
    }
  }

  const engineResult = createMutableEngineResult({
    engineName: 'experimental',
    engineVersion: '0.1.0-ir',
    layers: LAYERS,
    scanId: `experimental_${sourceInfo.id || sourceInfo.repo || 'unknown'}_${sourceInfo.pr || Date.now()}`,
    findings: annotatedFindings.map((f, i) => ({
      id: f.id || `experimental_${i}`,
      type: f.type || f.category || 'generic',
      severity: f.severity || 'INFO',
      riskLevel: f.risk || 0,
      confidence: f.confidence || 'medium',
      message: f.description || f.message || '',
      file: sourceInfo.filename || sourceInfo.file,
      line: f.line,
      snippet: f.snippet,
      sourceEngine: f.source || 'IR',
      techniqueId: f.id,
      capability: f.category,
    })),
    riskScore,
    verdict,
    riskBand: riskScore >= 0.75 ? 'CRITICAL' : riskScore >= 0.55 ? 'HIGH' : riskScore >= 0.35 ? 'MODERATE' : riskScore > 0 ? 'LOW' : 'NEGLIGIBLE',
    decisionConfidence: maxConfidence === 'high' ? 0.95 : maxConfidence === 'medium' ? 0.6 : 0.2,
    evidenceGraph: propertyGraphJSON || undefined,
    capabilities,
    irSummary: Object.keys(irSummary).length > 0 ? irSummary : undefined,
    taxonomyMatches: Object.keys(taxonomyMatches).length > 0 ? taxonomyMatches : undefined,
    statistics: {
      analysisTimeMs: latencyMs,
      memoryBytes: Math.max(0, Math.round(memoryBytes)),
      filesAnalyzed: 1,
      filesWithFindings: annotatedFindings.length > 0 ? 1 : 0,
      totalFindings: annotatedFindings.length,
      layersExecuted: LAYERS.length,
      symbolsResolved: result.propertyGraph?.stats?.totalNodes || 0,
      stringsDecoded: irFindings.length,
    },
    metadata: {
      detectorVerdict: result.verdict,
      summary: summary,
      source: sourceInfo,
      maxConfidence,
    },
  });

  return engineResult;
}

/**
 * Source-only mode (no code available).
 * Runs normalizer on empty code — returns baseline-compatible result
 * for comparison when real code isn't accessible.
 */
function produceFromSource(source, options = {}) {
  return produceFromCode('', source, options);
}

module.exports = { produceFromCode, produceFromSource, LAYERS, stripDeadCode };
