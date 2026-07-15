'use strict';

/**
 * EngineComparator — diff two EngineResult objects.
 *
 * Produces a structured comparison report covering:
 *   - Finding diff (added, removed, changed severity)
 *   - Risk score delta
 *   - Verdict change
 *   - Capability coverage
 *   - Evidence graph quality (node/edge counts, connected components)
 *   - Performance delta
 *   - IR / taxonomy coverage (experimental-only metrics)
 */

function compareResults(baseline, experimental) {
  const report = {
    timestamp: Date.now(),
    baseline: {
      engineName: baseline.engineName,
      engineVersion: baseline.engineVersion,
      verdict: baseline.verdict,
      riskScore: baseline.riskScore,
      riskBand: baseline.riskBand,
      totalFindings: baseline.statistics.totalFindings,
      analysisTimeMs: baseline.statistics.analysisTimeMs,
    },
    experimental: {
      engineName: experimental.engineName,
      engineVersion: experimental.engineVersion,
      verdict: experimental.verdict,
      riskScore: experimental.riskScore,
      riskBand: experimental.riskBand,
      totalFindings: experimental.statistics.totalFindings,
      analysisTimeMs: experimental.statistics.analysisTimeMs,
    },
    diff: {
      verdictChange: compareVerdicts(baseline.verdict, experimental.verdict),
      riskScoreDelta: round3((experimental.riskScore || 0) - (baseline.riskScore || 0)),
      findingDiff: diffFindings(baseline.findings || [], experimental.findings || []),
      capabilityDiff: diffCapabilities(baseline.capabilities || [], experimental.capabilities || []),
      performanceDiff: diffPerformance(baseline.statistics, experimental.statistics),
    },
    experimentalOnly: {},
    quality: {},
    summary: {},
  };

  // Experimental-only metrics
  if (experimental.irSummary) {
    report.experimentalOnly.irSummary = experimental.irSummary;
  }
  if (experimental.taxonomyMatches) {
    report.experimentalOnly.taxonomyMatches = experimental.taxonomyMatches;
  }
  if (experimental.evidenceGraph) {
    report.experimentalOnly.evidenceGraph = assessGraphQuality(experimental.evidenceGraph);
  }

  // Quality scoring
  report.quality = assessQuality(baseline, experimental, report);

  // Summary
  report.summary = buildSummary(report);

  return Object.freeze(report);
}

function round3(n) {
  return Math.round(n * 1000) / 1000;
}

function compareVerdicts(b, e) {
  const order = { 'PASS': 0, 'REVIEW': 1, 'BLOCK': 2 };
  const bv = order[b] || 0;
  const ev = order[e] || 0;
  if (ev > bv) return 'ESCALATED';
  if (ev < bv) return 'DEESCALATED';
  return 'UNCHANGED';
}

function diffFindings(baselineFindings, experimentalFindings) {
  const baselineMap = new Map();
  for (const f of baselineFindings) {
    baselineMap.set(f.id || f.type + '_' + f.file + '_' + f.line, f);
  }

  const experimentalMap = new Map();
  for (const f of experimentalFindings) {
    experimentalMap.set(f.id || f.type + '_' + f.file + '_' + f.line, f);
  }

  const added = [];
  const removed = [];
  const changed = [];
  const preserved = [];

  for (const [key, f] of experimentalMap) {
    if (!baselineMap.has(key)) {
      added.push({ id: f.id, type: f.type, severity: f.severity, message: f.message });
    } else {
      const b = baselineMap.get(key);
      if (b.severity !== f.severity) {
        changed.push({ id: f.id, type: f.type, from: b.severity, to: f.severity });
      } else {
        preserved.push({ id: f.id, type: f.type, severity: f.severity });
      }
    }
  }

  for (const [key, f] of baselineMap) {
    if (!experimentalMap.has(key)) {
      removed.push({ id: f.id, type: f.type, severity: f.severity, message: f.message });
    }
  }

  return { added, removed, changed, preserved, addedCount: added.length, removedCount: removed.length, changedCount: changed.length, preservedCount: preserved.length };
}

function diffCapabilities(baselineCaps, experimentalCaps) {
  const bSet = new Set(baselineCaps);
  const eSet = new Set(experimentalCaps);

  const added = [...eSet].filter(c => !bSet.has(c));
  const removed = [...bSet].filter(c => !eSet.has(c));
  const shared = [...bSet].filter(c => eSet.has(c));

  return {
    added,
    removed,
    shared,
    addedCount: added.length,
    removedCount: removed.length,
    sharedCount: shared.length,
    totalBaseline: bSet.size,
    totalExperimental: eSet.size,
  };
}

function diffPerformance(bStats, eStats) {
  const timeMs = (eStats?.analysisTimeMs || 0) - (bStats?.analysisTimeMs || 0);
  const timePct = bStats?.analysisTimeMs > 0 ? ((eStats?.analysisTimeMs || 0) / bStats.analysisTimeMs - 1) * 100 : 0;
  const memBytes = (eStats?.memoryBytes || 0) - (bStats?.memoryBytes || 0);

  return {
    timeDeltaMs: timeMs,
    timeDeltaPct: round3(timePct),
    memoryDeltaBytes: memBytes,
    findingsDelta: (eStats?.totalFindings || 0) - (bStats?.totalFindings || 0),
  };
}

function assessGraphQuality(graph) {
  if (!graph) return null;
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  const types = {};
  for (const n of nodes) {
    types[n.type] = (types[n.type] || 0) + 1;
  }

  const relations = {};
  for (const e of edges) {
    relations[e.relation] = (relations[e.relation] || 0) + 1;
  }

  // Simple connected components count (union-find)
  const nodeIds = new Map();
  nodes.forEach((n, i) => nodeIds.set(n.id, i));
  const parent = nodes.map((_, i) => i);
  function find(x) { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
  function union(a, b) { const ra = find(a), rb = find(b); if (ra !== rb) parent[rb] = ra; }
  for (const e of edges) {
    const fi = nodeIds.get(e.from);
    const ti = nodeIds.get(e.to);
    if (fi !== undefined && ti !== undefined) union(fi, ti);
  }
  const components = new Set();
  nodes.forEach((_, i) => components.add(find(i)));

  return {
    totalNodes: nodes.length,
    totalEdges: edges.length,
    nodeTypes: types,
    edgeRelations: relations,
    connectedComponents: components.size,
    density: nodes.length > 1 ? round3(2 * edges.length / (nodes.length * (nodes.length - 1))) : 0,
  };
}

function assessQuality(baseline, experimental, report) {
  const quality = {
    coverage: {},
    reasoning: {},
    score: 0,
    maxScore: 10,
  };

  // Coverage: did experimental add new capabilities?
  const capDiff = report.diff.capabilityDiff;
  quality.coverage.newCapabilities = capDiff.addedCount;
  quality.coverage.lostCapabilities = capDiff.removedCount;
  quality.coverage.capabilityExpansion = capDiff.addedCount - capDiff.removedCount;

  // Reasoning: does experimental have IR / taxonomy evidence?
  quality.reasoning.hasIR = !!experimental.irSummary;
  quality.reasoning.hasTaxonomy = !!experimental.taxonomyMatches;
  quality.reasoning.hasEvidenceGraph = !!experimental.evidenceGraph;
  quality.reasoning.hasGraph = experimental.evidenceGraph && experimental.evidenceGraph.nodes && experimental.evidenceGraph.nodes.length > 0;

  // Composite score (higher = better experimental)
  let score = 5; // start neutral

  // +1 for detecting more findings
  if (report.diff.findingDiff.addedCount > report.diff.findingDiff.removedCount) score += 1;
  if (report.diff.findingDiff.removedCount === 0 && report.diff.findingDiff.addedCount > 0) score += 0.5;

  // +1 for new capabilities
  if (capDiff.addedCount > 0) score += 1;

  // +1 for evidence graph
  if (quality.reasoning.hasGraph) score += 1;

  // +1 for IR summary
  if (quality.reasoning.hasIR) score += 1;

  // +0.5 for taxonomy matches
  if (quality.reasoning.hasTaxonomy) score += 0.5;

  quality.score = Math.min(10, Math.max(0, round3(score)));

  return quality;
}

function buildSummary(report) {
  const parts = [];

  const { verdictChange, riskScoreDelta, findingDiff, capabilityDiff, performanceDiff } = report.diff;

  parts.push(`Verdict: ${report.baseline.verdict} → ${report.experimental.verdict} (${verdictChange})`);
  parts.push(`Risk Score: ${report.baseline.riskScore} → ${report.experimental.riskScore} (${riskScoreDelta >= 0 ? '+' : ''}${riskScoreDelta})`);

  const fc = findingDiff;
  parts.push(`Findings: +${fc.addedCount} / -${fc.removedCount} / ~${fc.changedCount} / =${fc.preservedCount} (added/removed/changed/preserved)`);

  const cc = capabilityDiff;
  parts.push(`Capabilities: +${cc.addedCount} / -${cc.removedCount} / ${cc.sharedCount} shared (baseline: ${cc.totalBaseline}, experimental: ${cc.totalExperimental})`);

  const pd = performanceDiff;
  parts.push(`Performance: ${pd.timeDeltaMs >= 0 ? '+' : ''}${pd.timeDeltaMs}ms (${pd.timeDeltaPct >= 0 ? '+' : ''}${pd.timeDeltaPct}%)`);

  const q = report.quality;
  parts.push(`Quality Score: ${q.score}/${q.maxScore}`);

  return {
    text: parts.join(' | '),
    lines: parts,
    verdictChange,
    riskScoreDelta,
    findingNetDelta: findingDiff.addedCount - findingDiff.removedCount,
    qualityScore: q.score,
    qualityMaxScore: q.maxScore,
  };
}

/**
 * Compare multiple passes and produce an aggregate report.
 */
function aggregateComparisons(comparisons) {
  if (!comparisons || comparisons.length === 0) return null;

  const totals = {
    passes: comparisons.length,
    verdictChanges: { ESCALATED: 0, DEESCALATED: 0, UNCHANGED: 0 },
    totalRiskDelta: 0,
    totalFindingsAdded: 0,
    totalFindingsRemoved: 0,
    totalFindingsChanged: 0,
    totalCapabilitiesAdded: 0,
    totalCapabilitiesRemoved: 0,
    totalTimeDeltaMs: 0,
    qualityScores: [],
  };

  for (const comp of comparisons) {
    totals.verdictChanges[comp.diff.verdictChange]++;
    totals.totalRiskDelta += comp.diff.riskScoreDelta;
    totals.totalFindingsAdded += comp.diff.findingDiff.addedCount;
    totals.totalFindingsRemoved += comp.diff.findingDiff.removedCount;
    totals.totalFindingsChanged += comp.diff.findingDiff.changedCount;
    totals.totalCapabilitiesAdded += comp.diff.capabilityDiff.addedCount;
    totals.totalCapabilitiesRemoved += comp.diff.capabilityDiff.removedCount;
    totals.totalTimeDeltaMs += comp.diff.performanceDiff.timeDeltaMs;
    totals.qualityScores.push(comp.quality.score);
  }

  const avg = (arr) => arr.length > 0 ? round3(arr.reduce((s, v) => s + v, 0) / arr.length) : 0;

  return Object.freeze({
    passes: totals.passes,
    verdictChanges: totals.verdictChanges,
    avgRiskDelta: avg([...comparisons.map(c => c.diff.riskScoreDelta)]),
    totalFindingsAdded: totals.totalFindingsAdded,
    totalFindingsRemoved: totals.totalFindingsRemoved,
    avgFindingsAddedPerPass: round3(totals.totalFindingsAdded / totals.passes),
    avgFindingsRemovedPerPass: round3(totals.totalFindingsRemoved / totals.passes),
    totalCapabilitiesAdded: totals.totalCapabilitiesAdded,
    totalCapabilitiesRemoved: totals.totalCapabilitiesRemoved,
    avgTimeDeltaMs: round3(totals.totalTimeDeltaMs / totals.passes),
    avgQualityScore: avg(totals.qualityScores),
    minQualityScore: Math.min(...totals.qualityScores),
    maxQualityScore: Math.max(...totals.qualityScores),
  });
}

/**
 * Ground Truth Evaluation
 *
 * Compares an engine result against known expected values.
 * Expected is typically derived from the test corpus or MutationLab.
 *
 * @typedef {Object} GroundTruth
 * @property {string|null} verdict           — 'PASS'|'REVIEW'|'BLOCK'|null
 * @property {number|null} riskScore         — 0–1 or null
 * @property {Array<{type:string, severity:string}>} findings
 * @property {string[]} capabilities
 * @property {string|null} source            — 'mutation_lab'|'clean_corpus'|'manual'|null
 *
 * @typedef {Object} GroundTruthEval
 * @property {string} engineName
 * @property {boolean} hasGroundTruth
 * @property {Object} verdictMatch
 * @property {boolean} verdictMatch.accurate
 * @property {string} expected
 * @property {string} actual
 * @property {Object} findingMetrics
 * @property {number} truePositives
 * @property {number} falsePositives
 * @property {number} falseNegatives
 * @property {number} precision        — TP/(TP+FP) or 1 if no findings
 * @property {number} recall           — TP/(TP+FN) or 1 if no expected findings
 * @property {number} f1               — 2*P*R/(P+R) or 1 if both 0
 * @property {Object} capabilityMetrics
 * @property {number} expectedCapabilities
 * @property {number} matchedCapabilities
 * @property {number} coverage         — matched/expected or 1 if none expected
 * @property {string[]} missingCapabilities
 * @property {string[]} unexpectedCapabilities
 * @property {Object} riskScoreDelta   — |expected - actual|
 */

function evaluateAgainstGroundTruth(expected, actual) {
  const empty = { verdict: null, riskScore: null, findings: [], capabilities: [] };
  const gt = expected || empty;

  const hasGT = gt.verdict !== null && gt.verdict !== undefined;

  if (!hasGT) {
    return {
      engineName: actual.engineName,
      hasGroundTruth: false,
      verdictMatch: { accurate: null, expected: null, actual: actual.verdict },
      findingMetrics: { truePositives: 0, falsePositives: 0, falseNegatives: 0, precision: null, recall: null, f1: null },
      capabilityMetrics: { expectedCapabilities: 0, matchedCapabilities: 0, coverage: null, missingCapabilities: [], unexpectedCapabilities: [] },
      riskScoreDelta: null,
    };
  }

  // ── Verdict Match ──
  // Normalize both for comparison
  const normVerdict = (v) => {
    if (!v) return null;
    const map = { 'CRITICAL': 'BLOCK', 'SUSPICIOUS': 'REVIEW', 'WARNING': 'REVIEW', 'INFO': 'PASS', 'CLEAN': 'PASS' };
    return map[v] || v;
  };
  const expectedV = normVerdict(gt.verdict);
  const actualV = normVerdict(actual.verdict);
  const verdictAccurate = expectedV === actualV;

  // ── Finding Metrics ──
  const expectedFindings = (gt.findings || []).map(f => f.type || f.techniqueId || f).filter(Boolean);
  const actualFindings = (actual.findings || []).map(f => f.techniqueId || f.type || f.id || f).filter(Boolean);

  const expectedSet = new Set(expectedFindings);
  const actualSet = new Set(actualFindings);

  const truePositives = [...expectedSet].filter(t => actualSet.has(t)).length;
  const falsePositives = [...actualSet].filter(t => !expectedSet.has(t)).length;
  const falseNegatives = [...expectedSet].filter(t => !actualSet.has(t)).length;

  const precision = (truePositives + falsePositives) > 0
    ? round3(truePositives / (truePositives + falsePositives))
    : 1.0;
  const recall = (truePositives + falseNegatives) > 0
    ? round3(truePositives / (truePositives + falseNegatives))
    : 1.0;
  const f1 = (precision + recall) > 0
    ? round3(2 * precision * recall / (precision + recall))
    : 1.0;

  // ── Capability Metrics ──
  const expectedCaps = new Set(gt.capabilities || []);
  const actualCaps = new Set(actual.capabilities || []);

  const matchedCaps = [...expectedCaps].filter(c => actualCaps.has(c));
  const missingCaps = [...expectedCaps].filter(c => !actualCaps.has(c));
  const unexpectedCaps = [...actualCaps].filter(c => !expectedCaps.has(c));

  const capCoverage = expectedCaps.size > 0
    ? round3(matchedCaps.length / expectedCaps.size)
    : 1.0;

  // ── Risk Score Delta ──
  const riskDelta = (gt.riskScore !== null && gt.riskScore !== undefined)
    ? round3(Math.abs((actual.riskScore || 0) - gt.riskScore))
    : null;

  // ── Failure Reason (why verdict was inaccurate) ──
  let failureReason = null;
  if (hasGT && !verdictAccurate) {
    if (actualFindings.length === 0) {
      failureReason = 'NO_MATCH';
    } else if (actual.decisionConfidence !== undefined && actual.decisionConfidence < 0.35) {
      failureReason = 'LOW_CONFIDENCE';
    } else if (missingCaps.length > 0) {
      failureReason = 'WRONG_CAPABILITY';
    } else {
      failureReason = 'RULE_MISSING';
    }
  }

  return {
    engineName: actual.engineName,
    hasGroundTruth: true,
    verdictMatch: {
      accurate: verdictAccurate,
      expected: expectedV,
      actual: actualV,
    },
    failureReason,
    findingMetrics: {
      truePositives,
      falsePositives,
      falseNegatives,
      precision,
      recall,
      f1,
    },
    capabilityMetrics: {
      expectedCapabilities: expectedCaps.size,
      matchedCapabilities: matchedCaps.length,
      coverage: capCoverage,
      missingCapabilities: missingCaps,
      unexpectedCapabilities: unexpectedCaps,
    },
    riskScoreDelta: riskDelta,
  };
}

/**
 * Evaluate both engines against the same ground truth.
 */
function evaluateBothEngines(expected, baseline, experimental) {
  return {
    baseline: evaluateAgainstGroundTruth(expected, baseline),
    experimental: evaluateAgainstGroundTruth(expected, experimental),
    expected: expected ? {
      verdict: expected.verdict,
      riskScore: expected.riskScore,
      findingsCount: (expected.findings || []).length,
      capabilitiesCount: (expected.capabilities || []).length,
      source: expected.source,
    } : null,
  };
}

module.exports = { compareResults, aggregateComparisons, evaluateAgainstGroundTruth, evaluateBothEngines };
