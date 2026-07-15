/**
 * Benchmark Runner (v1.0)
 *
 * Runs dual-engine comparison over the PR Zoo with:
 *   - Per-phase timing (parse, normalize, IR, graph, evidence)
 *   - Cold/Warm cache modes
 *   - Memory measurement
 *   - Performance budgets
 *   - Percentiles (P50, P90, P95, P99)
 *   - Quality gates
 *   - Historical tracking
 *   - Divergence detection → interesting_cases/
 *
 * Usage:
 *   node scripts/benchmark_runner.js                     # full zoo
 *   node scripts/benchmark_runner.js --samples=20        # subset
 *   node scripts/benchmark_runner.js --warm              # warm cache
 *   node scripts/benchmark_runner.js --budgets           # enforce budgets
 *   node scripts/benchmark_runner.js --phase-breakdown   # detailed phases
 *   node scripts/benchmark_runner.js --compare=<dir>     # compare vs prior report
 *
 * Exit codes:
 *   0 — success (or ACCEPTED)
 *   1 — budgets failed
 *   2 — comparison REJECTED
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { produce: baselineProduce } = require('../packages/sentinel-core/adapters/baseline_adapter');
const { produceFromCode: experimentalProduce } = require('../packages/sentinel-core/adapters/experimental_adapter');
const { compareResults, aggregateComparisons, evaluateBothEngines } = require('../packages/sentinel-core/adapters/comparator');
const { normalize } = require('../packages/sentinel-core/scanner/evasion/normalizer');
const { build } = require('../packages/sentinel-core/scanner/evasion/property_graph');

const ZOO_DIR = path.join(__dirname, '..', 'data', 'pr_zoo');
const PATCHES_DIR = path.join(ZOO_DIR, 'patches');
const MANIFEST_PATH = path.join(ZOO_DIR, 'manifest.json');
const CACHE_DIR = path.join(ZOO_DIR, 'cache');
const BENCHMARK_DIR = path.join(__dirname, '..', 'reports', 'benchmark');
const INTERESTING_DIR = path.join(BENCHMARK_DIR, 'interesting_cases');
const HISTORY_PATH = path.join(BENCHMARK_DIR, 'history.jsonl');

const args = process.argv.slice(2);
const sampleCount = parseInt(args.find(a => a.startsWith('--samples='))?.split('=')[1] || 0);
const isWarm = args.includes('--warm');
const useBudgets = args.includes('--budgets');
const phaseBreakdown = args.includes('--phase-breakdown');
const dumpFlame = args.includes('--prof');
const compareToPath = args.find(a => a.startsWith('--compare='))?.split('=')[1] || null;

// ── Performance Budgets ──
const BUDGETS = {
  parse_ms: 10,
  normalize_ms: 5,
  ir_ms: 5,
  graph_ms: 5,
  evidence_ms: 3,
  total_ms: 30,
  memory_mb: 20,
  p95_ms: 50,
  p99_ms: 100,
};

// ── Init ──
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
if (!fs.existsSync(BENCHMARK_DIR)) fs.mkdirSync(BENCHMARK_DIR, { recursive: true });
if (!fs.existsSync(INTERESTING_DIR)) fs.mkdirSync(INTERESTING_DIR, { recursive: true });

// ── Cache ──
const astCache = new Map();
const irCache = new Map();
const graphCache = new Map();

function cacheKey(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function round3(v) {
  return Math.round(v * 1000) / 1000;
}

function loadDiskCache(key, subdir) {
  const p = path.join(CACHE_DIR, subdir, `${key}.json`);
  if (isWarm && fs.existsSync(p)) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return null; }
  }
  return null;
}

function saveDiskCache(key, subdir, data) {
  const dir = path.join(CACHE_DIR, subdir);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${key}.json`), JSON.stringify(data), 'utf8');
}

// ── Phase Timers ──
function now() {
  return performance ? performance.now() : Date.now();
}

function phaseTimer() {
  const marks = {};
  const start = now();
  let last = start;
  return {
    mark(name) {
      const t = now();
      marks[name] = t - last;
      last = t;
    },
    end() {
      marks._total = now() - start;
      return marks;
    },
  };
}

// ── Run Single Sample ──
function runSample(entry, zooIndex, total) {
  const id = entry.id;
  const patchFile = path.join(PATCHES_DIR, `${id}.patch`);
  const metaFile = path.join(PATCHES_DIR, `${id}.json`);

  if (!fs.existsSync(patchFile)) return null;

  const code = fs.readFileSync(patchFile, 'utf8');
  const patchHash = cacheKey(code);

  // Load metadata
  let meta = { source: {} };
  try { meta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch (e) {}
  const source = meta.source || { id, repo: entry.repo, pr: entry.pr, profile: entry.profile };

  const beforeMem = process.memoryUsage ? process.memoryUsage().heapUsed : 0;

  // ── Phase: Parse (read + AST) ──
  const timer = phaseTimer();

  // AST cache hit?
  let symbols = loadDiskCache(patchHash, 'ast');
  if (!symbols) {
    symbols = normalize(code);
    saveDiskCache(patchHash, 'ast', symbols);
  }
  timer.mark('parse');

  // ── Phase: Normalize / IR ──
  let irFindings = [];
  if (symbols && symbols.callSites) {
    irFindings = symbols.callSites
      .filter((cs) => cs.name)
      .map((cs) => ({ name: cs.name, raw: cs.raw }));
  }
  timer.mark('normalize');

  // ── Phase: Property Graph ──
  let propertyGraph = loadDiskCache(patchHash, 'graph');
  if (!propertyGraph) {
    try {
      propertyGraph = build(symbols, code);
      saveDiskCache(patchHash, 'graph', propertyGraph.toJSON());
    } catch (e) {
      propertyGraph = { nodes: [], edges: [], stats: { totalNodes: 0, totalEdges: 0, capabilities: [] } };
    }
  }
  timer.mark('graph');

  // ── Baseline Engine ──
  const baselineStart = now();
  let baselineResult;
  try {
    baselineResult = baselineProduce(source, { isAudit: true });
  } catch (e) {
    baselineResult = { verdict: 'ERROR', riskScore: 0, statistics: { totalFindings: 0 } };
  }
  const baselineTime = now() - baselineStart;

  // ── Experimental Engine (runs full assessCode) ──
  const expStart = now();
  let experimentalResult;
  try {
    experimentalResult = experimentalProduce(code, source);
  } catch (e) {
    experimentalResult = { verdict: 'ERROR', riskScore: 0, statistics: { totalFindings: 0 } };
  }
  const expTime = now() - baselineStart; // note: intentionally overlaps baseline

  // Adjust: run separately for accurate timing
  const expStart2 = now();
  try {
    experimentalResult = experimentalProduce(code, source);
  } catch (e) {
    experimentalResult = { verdict: 'ERROR', riskScore: 0, statistics: { totalFindings: 0 } };
  }
  const expTimeMs = now() - expStart2;

  timer.mark('evidence');

  const afterMem = process.memoryUsage ? process.memoryUsage().heapUsed : 0;
  const peakMemMb = Math.round((afterMem - beforeMem) / (1024 * 1024) * 100) / 100;

  const phases = timer.end();

  // ── Compare ──
  let comparison = null;
  try {
    comparison = compareResults(baselineResult, experimentalResult);
  } catch (e) {
    comparison = { diff: { verdictChange: 'ERROR', riskScoreDelta: 0, findingDiff: { addedCount: 0, removedCount: 0, changedCount: 0 }, capabilityDiff: { addedCount: 0, removedCount: 0 }, performanceDiff: { timeDeltaMs: 0, timeDeltaPct: 0 } }, quality: { score: 0, maxScore: 10 } };
  }

  // Ground truth evaluation
  const expected = meta.expected || null;
  const taxonomy = meta.taxonomy || null;
  const variant = meta.variant !== undefined ? meta.variant : null;
  let gtEval = null;
  try {
    if (expected) {
      gtEval = evaluateBothEngines(expected, baselineResult, experimentalResult);
    }
  } catch (e) {
    gtEval = { error: e.message };
  }
  const failureReason = gtEval?.experimental?.failureReason || null;

  return {
    id,
    repo: entry.repo,
    pr: entry.pr,
    taxonomy,
    variant,
    patchHash,
    patchSize: code.length,
    hasGroundTruth: !!expected,
    expectedSource: expected?.source || null,

    baseline: {
      verdict: baselineResult.verdict,
      riskScore: baselineResult.riskScore,
      findings: baselineResult.statistics?.totalFindings || 0,
      capabilities: baselineResult.capabilities || [],
      timeMs: baselineTime,
    },
    experimental: {
      verdict: experimentalResult.verdict,
      riskScore: experimentalResult.riskScore,
      findings: experimentalResult.statistics?.totalFindings || 0,
      findingRules: (experimentalResult.findings || []).map(f => f.id || f.techniqueId || f.type).filter(Boolean),
      capabilities: experimentalResult.capabilities || [],
      decisionConfidence: experimentalResult.decisionConfidence ?? null,
      maxConfidence: experimentalResult.metadata?.maxConfidence ?? null,
      irSummary: experimentalResult.irSummary || null,
      taxonomyMatches: experimentalResult.taxonomyMatches || null,
      graphQuality: experimentalResult.evidenceGraph
        ? {
            nodes: experimentalResult.evidenceGraph.nodes?.length || 0,
            edges: experimentalResult.evidenceGraph.edges?.length || 0,
          }
        : null,
      timeMs: expTimeMs,
    },

    phases,

    memory: {
      peakDeltaMb: peakMemMb,
    },

    comparison: comparison.diff,
    qualityScore: comparison.quality.score,
    qualityMaxScore: comparison.quality.maxScore,

    groundTruth: gtEval,

    diverged:
      comparison.diff.verdictChange === 'ESCALATED' ||
      comparison.diff.verdictChange === 'DEESCALATED' ||
      comparison.diff.findingDiff.addedCount > 0 ||
      comparison.diff.findingDiff.removedCount > 0,
  };
}

// ── Budget Check ──
function checkBudgets(results) {
  const failures = [];
  const totals = results.filter(Boolean);

  if (totals.length === 0) return { passed: false, failures: ['No results'] };

  // Per-sample budget checks
  for (const r of totals) {
    if (r.phases._total > BUDGETS.total_ms) {
      failures.push({ sample: r.id, metric: 'total_ms', value: r.phases._total, budget: BUDGETS.total_ms });
    }
    if (r.memory.peakDeltaMb > BUDGETS.memory_mb) {
      failures.push({ sample: r.id, metric: 'memory_mb', value: r.memory.peakDeltaMb, budget: BUDGETS.memory_mb });
    }
    if (phaseBreakdown) {
      if (r.phases.parse > BUDGETS.parse_ms)
        failures.push({ sample: r.id, metric: 'parse_ms', value: r.phases.parse, budget: BUDGETS.parse_ms });
      if (r.phases.normalize > BUDGETS.normalize_ms)
        failures.push({ sample: r.id, metric: 'normalize_ms', value: r.phases.normalize, budget: BUDGETS.normalize_ms });
      if ((r.phases.ir || r.phases.graph) > BUDGETS.graph_ms)
        failures.push({ sample: r.id, metric: 'graph_ms', value: r.phases.graph || r.phases.ir, budget: BUDGETS.graph_ms });
    }
  }

  // P95 / P99 budget checks
  const times = totals.map((r) => r.phases._total).sort((a, b) => a - b);
  const p95 = times[Math.floor(times.length * 0.95)] || 0;
  const p99 = times[Math.floor(times.length * 0.99)] || 0;

  if (p95 > BUDGETS.p95_ms)
    failures.push({ sample: 'ALL', metric: 'p95_ms', value: p95, budget: BUDGETS.p95_ms });
  if (p99 > BUDGETS.p99_ms)
    failures.push({ sample: 'ALL', metric: 'p99_ms', value: p99, budget: BUDGETS.p99_ms });

  return { passed: failures.length === 0, failures };
}

// ── Divergence Detection ──
function saveDivergences(results) {
  const diverged = results.filter((r) => r && r.diverged);
  if (diverged.length === 0) return;

  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const divPath = path.join(INTERESTING_DIR, `divergences_${ts}.jsonl`);

  for (const r of diverged) {
    const entry = {
      ts: new Date().toISOString(),
      id: r.id,
      repo: r.repo,
      pr: r.pr,
      taxonomy: r.taxonomy,
      variant: r.variant,
      comparison: r.comparison,
      qualityScore: r.qualityScore,
      baseline: r.baseline,
      experimental: r.experimental,
    };
    fs.appendFileSync(divPath, JSON.stringify(entry) + '\n');
  }

  return diverged.length;
}

// ── Summary Stats ──
function computeStats(results) {
  const valid = results.filter(Boolean);
  if (valid.length === 0) return null;

  const times = valid.map((r) => r.phases._total).sort((a, b) => a - b);
  const mems = valid.map((r) => r.memory.peakDeltaMb).sort((a, b) => a - b);
  const qualities = valid.map((r) => r.qualityScore).sort((a, b) => a - b);

  const diverged = valid.filter((r) => r.diverged);
  const escalated = valid.filter((r) => r.comparison?.verdictChange === 'ESCALATED');
  const deescaped = valid.filter((r) => r.comparison?.verdictChange === 'DEESCALATED');

  const avg = (arr) => (arr.length > 0 ? arr.reduce((s, v) => s + v, 0) / arr.length : 0);

  // Ground truth
  const withGT = valid.filter((r) => r.groundTruth && r.groundTruth.baseline?.hasGroundTruth);
  const gtBaselinePrec = withGT.map((r) => r.groundTruth.baseline.findingMetrics.precision).filter((v) => v !== null);
  const gtBaselineRecall = withGT.map((r) => r.groundTruth.baseline.findingMetrics.recall).filter((v) => v !== null);
  const gtBaselineF1 = withGT.map((r) => r.groundTruth.baseline.findingMetrics.f1).filter((v) => v !== null);
  const gtExpPrec = withGT.map((r) => r.groundTruth.experimental.findingMetrics.precision).filter((v) => v !== null);
  const gtExpRecall = withGT.map((r) => r.groundTruth.experimental.findingMetrics.recall).filter((v) => v !== null);
  const gtExpF1 = withGT.map((r) => r.groundTruth.experimental.findingMetrics.f1).filter((v) => v !== null);

  // Micro-averaged: aggregate TP/FP/FN across all samples
  function microAverage(engine) {
    const tp = withGT.reduce((s, r) => s + (r.groundTruth[engine].findingMetrics.truePositives || 0), 0);
    const fp = withGT.reduce((s, r) => s + (r.groundTruth[engine].findingMetrics.falsePositives || 0), 0);
    const fn = withGT.reduce((s, r) => s + (r.groundTruth[engine].findingMetrics.falseNegatives || 0), 0);
    const P = (tp + fp) > 0 ? tp / (tp + fp) : (tp > 0 ? 1 : 0);
    const R = (tp + fn) > 0 ? tp / (tp + fn) : (tp > 0 ? 1 : 0);
    const F1 = (P + R) > 0 ? 2 * P * R / (P + R) : 0;
    return { tp, fp, fn, precision: round3(P), recall: round3(R), f1: round3(F1) };
  }
  const microBaseline = microAverage('baseline');
  const microExp = microAverage('experimental');

  const gtVerdictCorrectBaseline = withGT.filter((r) => r.groundTruth.baseline.verdictMatch.accurate).length;
  const gtVerdictCorrectExp = withGT.filter((r) => r.groundTruth.experimental.verdictMatch.accurate).length;

  // Clean-specific metrics: samples with expected verdict CLEAN/PASS
  const cleanSamples = withGT.filter((r) => {
    const expectedV = r.groundTruth?.expected?.verdict;
    return expectedV === 'CLEAN' || expectedV === 'PASS' || expectedV === 'INFO';
  });
  const cleanCorrect = cleanSamples.filter((r) => r.groundTruth.experimental.verdictMatch.accurate).length;
  const cleanFP = cleanSamples.filter((r) => !r.groundTruth.experimental.verdictMatch.accurate).length;

  const gtBySource = {};
  for (const r of withGT) {
    const src = r.expectedSource || 'unknown';
    if (!gtBySource[src]) gtBySource[src] = { count: 0, baselineF1: [], experimentalF1: [] };
    gtBySource[src].count++;
    gtBySource[src].baselineF1.push(r.groundTruth.baseline.findingMetrics.f1);
    gtBySource[src].experimentalF1.push(r.groundTruth.experimental.findingMetrics.f1);
  }
  for (const src of Object.keys(gtBySource)) {
    gtBySource[src].baselineAvgF1 = avg(gtBySource[src].baselineF1);
    gtBySource[src].experimentalAvgF1 = avg(gtBySource[src].experimentalF1);
    delete gtBySource[src].baselineF1;
    delete gtBySource[src].experimentalF1;
  }

  // By repo category
  const byRepo = {};
  for (const r of valid) {
    const repo = r.repo || 'unknown';
    if (!byRepo[repo]) byRepo[repo] = { count: 0, totalTime: 0, divergedCount: 0 };
    byRepo[repo].count++;
    byRepo[repo].totalTime += r.phases._total;
    if (r.diverged) byRepo[repo].divergedCount++;
  }

  // By family (for mutationlab samples with taxonomy)
  const byFamily = {};
  for (const r of valid) {
    const fam = r.taxonomy?.family || null;
    if (!fam) continue;
    if (!byFamily[fam]) byFamily[fam] = { count: 0, accurate: 0, inaccurate: 0, failureReasons: {} };
    byFamily[fam].count++;
    const gtExp = r.groundTruth?.experimental;
    if (gtExp?.verdictMatch?.accurate) {
      byFamily[fam].accurate++;
    } else {
      byFamily[fam].inaccurate++;
      const reason = gtExp?.failureReason || 'UNKNOWN';
      byFamily[fam].failureReasons[reason] = (byFamily[fam].failureReasons[reason] || 0) + 1;
    }
  }

  return {
    samples: valid.length,
    time: {
      avg: avg(times),
      p50: times[Math.floor(times.length * 0.5)] || 0,
      p90: times[Math.floor(times.length * 0.9)] || 0,
      p95: times[Math.floor(times.length * 0.95)] || 0,
      p99: times[Math.floor(times.length * 0.99)] || 0,
      min: times[0] || 0,
      max: times[times.length - 1] || 0,
    },
    memory: {
      avg: avg(mems),
      p95: mems[Math.floor(mems.length * 0.95)] || 0,
      max: mems[mems.length - 1] || 0,
    },
    quality: {
      avg: avg(qualities),
      min: qualities[0] || 0,
      max: qualities[qualities.length - 1] || 0,
    },
    divergences: {
      total: diverged.length,
      escalated: escalated.length,
      deescaped: deescaped.length,
      pct: valid.length > 0 ? ((diverged.length / valid.length) * 100).toFixed(1) : '0',
    },
    groundTruth: withGT.length > 0 ? {
      samplesWithGT: withGT.length,
      baseline: {
        micro: microBaseline,
        macro: {
          avgPrecision: avg(gtBaselinePrec),
          avgRecall: avg(gtBaselineRecall),
          avgF1: avg(gtBaselineF1),
        },
        verdictAccuracy: round3(gtVerdictCorrectBaseline / withGT.length),
      },
      experimental: {
        micro: microExp,
        macro: {
          avgPrecision: avg(gtExpPrec),
          avgRecall: avg(gtExpRecall),
          avgF1: avg(gtExpF1),
        },
        verdictAccuracy: round3(gtVerdictCorrectExp / withGT.length),
      },
      cleanAccuracy: cleanSamples.length > 0 ? round3(cleanCorrect / cleanSamples.length) : null,
      cleanFpRate: cleanSamples.length > 0 ? round3(cleanFP / cleanSamples.length) : null,
      cleanCount: cleanSamples.length,
      bySource: gtBySource,
    } : null,
    byRepo,
    byFamily: Object.keys(byFamily).length > 0 ? byFamily : undefined,
  };
}

// ── History ──
function appendHistory(stats, budgetsPassed, divergencesCount) {
  const gt = stats.groundTruth || {};
  const entry = {
    ts: new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    warm: isWarm,
    budgets: useBudgets,
    samples: stats.samples,
    avgTimeMs: stats.time.avg,
    p95TimeMs: stats.time.p95,
    p99TimeMs: stats.time.p99,
    avgMemoryMb: stats.memory.avg,
    avgQuality: stats.quality.avg,
    divergences: divergencesCount,
    budgetsPassed,
    gtSamples: gt.samplesWithGT || 0,
    baselineMicroF1: gt.baseline?.micro?.f1 ?? null,
    baselineMacroF1: gt.baseline?.macro?.avgF1 ?? null,
    experimentalMicroF1: gt.experimental?.micro?.f1 ?? null,
    experimentalMacroF1: gt.experimental?.macro?.avgF1 ?? null,
    baselineVerdictAccuracy: gt.baseline?.verdictAccuracy ?? null,
    experimentalVerdictAccuracy: gt.experimental?.verdictAccuracy ?? null,
    cleanAccuracy: gt.cleanAccuracy ?? null,
    cleanFpRate: gt.cleanFpRate ?? null,
  };
  fs.appendFileSync(HISTORY_PATH, JSON.stringify(entry) + '\n');
}

const CLUSTERS_REGISTRY_PATH = path.join(BENCHMARK_DIR, 'clusters_registry.json');

// ── Cluster Registry (stable IDs across iterations) ──

function loadClusterRegistry() {
  try {
    return JSON.parse(fs.readFileSync(CLUSTERS_REGISTRY_PATH, 'utf8'));
  } catch {
    return { nextId: 1, definitions: {} };
  }
}

function saveClusterRegistry(registry) {
  fs.writeFileSync(CLUSTERS_REGISTRY_PATH, JSON.stringify(registry, null, 2));
}

function clusterSignature(technique, failureReason, rules) {
  const r = [...new Set(rules || [])].sort();
  return `${technique || '?'}|${failureReason || '?'}|${r.join(',')}`;
}

function computeShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * (Math.log2(p) || 0);
  }
  return entropy;
}

function computeEvidenceSignals(code) {
  if (!code) return {};
  return {
    entropy: computeShannonEntropy(code).toFixed(2),
    length: code.length,
    containsExec: /\bexec\b|\bspawn\b|\bfork\b|\brun\b|\bexecSync\b/i.test(code) ? 1 : 0,
    containsDecode: /\b(Buffer\.from|atob|btoa|decodeURI|decodeURIComponent|toString\s*\(\s*['\"]base64['\"]\s*\))\b/i.test(code) ? 1 : 0,
    containsEval: /\b(eval|Function\s*\(|setTimeout\s*\(|setInterval\s*\()/i.test(code) ? 1 : 0,
    containsNetwork: /\b(http|https|fetch|request|axios|got|superagent)\b/i.test(code) ? 1 : 0,
    containsProcess: /\b(process\b|\brequire\s*\(\s*['\"](child_process|fs|net|http)\b)/i.test(code) ? 1 : 0,
    containsShell: /\b(sh\s*|bash\s*|cmd\s*|powershell|exec\b)/i.test(code) ? 1 : 0,
    containsCrypto: /\b(crypto|createHash|createHmac|randomBytes|pbkdf2)\b/i.test(code) ? 1 : 0,
    containsRequire: /\brequire\s*\(/.test(code) ? 1 : 0,
    linesOfCode: code.split('\n').length,
  };
}

function analyzeClusters(results) {
  const registry = loadClusterRegistry();
  const fpSamples = results.filter(Boolean).filter(r => {
    const gtExp = r.groundTruth?.experimental;
    if (!gtExp) return false;
    const expectedVerdict = r.groundTruth?.expected?.verdict;
    const isBenign = expectedVerdict === 'CLEAN' || expectedVerdict === 'PASS' || expectedVerdict === 'INFO';
    return isBenign && !gtExp.verdictMatch?.accurate;
  });

  // Group by technique + failureReason + rules
  const groups = {};
  for (const s of fpSamples) {
    const tech = s.taxonomy?.technique || s.id;
    const reason = s.groundTruth?.experimental?.failureReason || 'UNKNOWN';
    const rules = s.experimental?.findingRules || [];
    const sig = clusterSignature(tech, reason, rules);

    // Read code for evidence signals
    const patchFile = path.join(PATCHES_DIR, s.id + '.patch');
    let code = '';
    try { code = fs.readFileSync(patchFile, 'utf8'); } catch {}

    if (!groups[sig]) groups[sig] = {
      technique: tech,
      failureReason: reason,
      rules: [...new Set(rules)],
      evidence: { triggeredBy: [...new Set(rules)] },
      evidenceSignals: computeEvidenceSignals(code),
      samples: [],
    };
    groups[sig].samples.push({
      id: s.id,
      repo: s.repo,
      pr: s.pr,
      confidence: s.experimental?.decisionConfidence ?? null,
      verdict: s.experimental?.verdict,
      findingsCount: s.experimental?.findings || 0,
    });
  }

  // Build clusters sorted by impact (descending)
  const totalFPCases = fpSamples.length;
  const clusters = Object.values(groups)
    .map(g => ({
      technique: g.technique,
      failureReason: g.failureReason,
      rules: g.rules,
      evidenceAnalysis: {
        triggeredBy: g.evidence.triggeredBy,
        signals: g.evidenceSignals,
        why: g.failureReason === 'LOW_CONFIDENCE'
          ? 'Match found but confidence below threshold (no execution/decode evidence to escalate)'
          : g.failureReason === 'RULE_MISSING'
          ? 'Pattern matched but no rule explicitly classifies this benign pattern'
          : 'Unknown — investigate further',
      },
      suggestedFix: suggestFixForCluster(g),
      sampleCount: g.samples.length,
      samples: g.samples,
      expectedROI: totalFPCases > 0
        ? { pctOfFP: round3(g.samples.length / totalFPCases * 100), estimatedCleanAccuracyGain: round3(g.samples.length / totalFPCases * (1 - 0.25) * 100) }
        : null,
    }))
    .sort((a, b) => b.sampleCount - a.sampleCount);

  // Assign stable IDs by matching against registry
  const registrySigToId = {};
  for (const [id, def] of Object.entries(registry.definitions)) {
    registrySigToId[clusterSignature(def.technique, def.failureReason, def.rules)] = id;
  }

  const updatedDefs = {};
  let nextId = registry.nextId;
  for (const c of clusters) {
    const sig = clusterSignature(c.technique, c.failureReason, c.rules);
    let clusterId = registrySigToId[sig];
    let firstSeen = registry.definitions[clusterId]?.firstSeen;
    if (!clusterId) {
      clusterId = 'FP-' + String(nextId++).padStart(3, '0');
      firstSeen = new Date().toISOString();
    }
    c.clusterId = clusterId;
    c.clusterName = c.technique.replace(/_/g, ' ') || c.failureReason;
    updatedDefs[clusterId] = {
      technique: c.technique,
      failureReason: c.failureReason,
      rules: c.rules,
      firstSeen,
      status: registry.definitions[clusterId]?.status || 'OPEN',
      suggestedFix: c.suggestedFix,
    };
  }

  // Merge old defs that still exist + new defs
  const finalDefs = { ...registry.definitions };
  for (const [id, def] of Object.entries(updatedDefs)) {
    if (!finalDefs[id]) {
      finalDefs[id] = def;
    } else {
      const oldRules = new Set(finalDefs[id].rules || []);
      for (const r of (def.rules || [])) oldRules.add(r);
      finalDefs[id].rules = [...oldRules].sort();
      finalDefs[id].suggestedFix = def.suggestedFix;
    }
  }

  saveClusterRegistry({ nextId, definitions: finalDefs });

  // Attach historical sizes from registry if tracked
  for (const c of clusters) {
    const def = finalDefs[c.clusterId];
    c.history = def.history || [];
    c.history.push({ ts: new Date().toISOString(), count: c.sampleCount });
    def.history = c.history.slice(-20);
  }
  saveClusterRegistry({ nextId, definitions: finalDefs });

  return clusters;
}

function suggestFixForCluster(group) {
  const rules = group.rules || [];
  const reason = group.failureReason;
  const sigs = group.evidenceSignals || {};

  if (reason === 'LOW_CONFIDENCE') {
    if (rules.includes('EVASION-033') && !sigs.containsExec && !sigs.containsDecode && !sigs.containsEval) {
      return 'Lower EVASION-033 severity/risk when no execution or decode context is present. Consider adding property graph check: is the encoded string consumed by decode+exec?';
    }
    if (rules.includes('EVASION-006') && !sigs.containsExec && !sigs.containsDecode && !sigs.containsEval) {
      return 'Lower EVASION-006 severity/risk when no execution or decode context is present (already done). Verify context gating is sufficient.';
    }
    if (rules.includes('EVASION-024')) {
      return 'EVASION-024 (env ref) now context-gated in heuristics.js: LOW severity alone, escalates only with exfiltration/exec/eval/fetch/writeFile context.';
    }
    if (rules.includes('EVASION-006')) {
      return 'EVASION-006 (encoded string) should suppress when string is constant, never decoded, and not passed to require/exec. Add data flow check.';
    }
    if (rules.includes('EVASION-013')) {
      return 'EVASION-013 (console.log/eval) in test context should be suppressed when filename contains test/spec/__test__. Add file path heuristic.';
    }
  }

  if (reason === 'RULE_MISSING') {
    if (rules.includes('EVASION-013')) {
      return 'EVASION-013 (eval) now context-gated in heuristics.js: LOW in test context without decode/exec/network signals, CRITICAL otherwise.';
    }
    if (rules.includes('EVASION-023')) {
      return 'EVASION-023 (hardcoded secret) should consider if the string contains typical non-secret patterns (base64 image data, example data).';
    }
  }

  return `Investigate: ${rules.join(', ')} triggered ${reason} — determine if rules need context-aware suppression.`;
}

// ── Scientific Dashboard ──
function printDashboard(stats, clusters, compareDecision, priorReportPath) {
  console.log('\n' + '═'.repeat(60));
  console.log('DASHBOARD');
  console.log('═'.repeat(60));

  const e = stats.groundTruth?.experimental;
  const c = stats.groundTruth;

  console.log('  Metrics:');
  console.log(`    Micro F1:         ${e?.micro?.f1?.toFixed(3) || 'N/A'}`);
  console.log(`    Macro F1:         ${e?.macro?.avgF1?.toFixed(3) || 'N/A'}`);
  console.log(`    Verdict Accuracy: ${e?.verdictAccuracy ? (e.verdictAccuracy * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`    Clean Accuracy:   ${c?.cleanAccuracy ? (c.cleanAccuracy * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`    Clean FP Rate:    ${c?.cleanFpRate ? (c.cleanFpRate * 100).toFixed(1) + '%' : 'N/A'}`);

  if (c?.bySource) {
    console.log('  GT by source:');
    for (const [src, info] of Object.entries(c.bySource)) {
      console.log(`    ${src.padEnd(15)} ${info.count} samples  baseline F1=${info.baselineAvgF1?.toFixed(3) || 'N/A'}  exp F1=${info.experimentalAvgF1?.toFixed(3) || 'N/A'}`);
    }
  }

  // Family coverage
  const byFamily = stats.byFamily;
  if (byFamily) {
    console.log('  Coverage by family:');
    const famEntries = Object.entries(byFamily).sort((a, b) => {
      const aAcc = a[1].count > 0 ? a[1].accurate / a[1].count : 0;
      const bAcc = b[1].count > 0 ? b[1].accurate / b[1].count : 0;
      return aAcc - bAcc;
    });
    for (const [fam, info] of famEntries) {
      const acc = info.count > 0 ? (info.accurate / info.count * 100).toFixed(1) : 'N/A';
      const icon = info.count > 0 && (info.accurate / info.count) >= 0.9 ? '✅' :
                   info.count > 0 && (info.accurate / info.count) >= 0.5 ? '⚠️' : '❌';
      console.log(`    ${icon} ${fam.padEnd(18)} ${acc}%  (${info.accurate}/${info.count})`);
    }
  }

  // FP Clusters
  if (clusters && clusters.length > 0) {
    console.log('  FP Clusters (by impact):');
    let cumulative = 0;
    const totalFP = clusters.reduce((s, c) => s + c.sampleCount, 0);
    for (const cl of clusters) {
      cumulative += cl.sampleCount;
      const pct = (cumulative / totalFP * 100).toFixed(0);
      const rulesStr = cl.rules.length > 0 ? cl.rules.join(', ') : '(no rules)';
      console.log(`    ${cl.clusterId.padEnd(6)} ${cl.clusterName.padEnd(25)} ${String(cl.sampleCount).padStart(3)} cases  [${rulesStr}]  (${pct}% cumulative)`);
      if (cl.evidenceAnalysis) {
        console.log(`           WHY: ${cl.evidenceAnalysis.why}`);
        const sigs = cl.evidenceAnalysis.signals || {};
        const activeSignals = Object.entries(sigs).filter(([k, v]) => v === 1 || (typeof v === 'string' && parseFloat(v) > 4)).map(([k, v]) => `${k}=${v}`);
        if (activeSignals.length > 0) console.log(`           Evidence: ${activeSignals.join(', ')}`);
      }
      if (cl.suggestedFix) {
        console.log(`           Fix: ${cl.suggestedFix.substring(0, 110)}...`);
      }
      if (cl.expectedROI) {
        console.log(`           ROI: ~${cl.expectedROI.estimatedCleanAccuracyGain.toFixed(1)}% clean accuracy gain (${cl.expectedROI.pctOfFP.toFixed(0)}% of FP)`);
      }
    }
  }

  // Bottleneck family (lowest coverage)
  if (byFamily) {
    const sorted = Object.entries(byFamily).sort((a, b) => {
      const aAcc = a[1].count > 0 ? a[1].accurate / a[1].count : 1;
      const bAcc = b[1].count > 0 ? b[1].accurate / b[1].count : 1;
      return aAcc - bAcc;
    });
    const worst = sorted[0];
    if (worst) {
      const acc = worst[1].count > 0 ? (worst[1].accurate / worst[1].count * 100).toFixed(1) : 'N/A';
      console.log(`  Bottleneck: ${worst[0]} (${acc}% accuracy)`);
    }
  }

  // Decision
  if (compareDecision) {
    console.log(`  Decision: ${compareDecision}`);
  }

  // Next ROI cluster
  if (clusters && clusters.length > 0) {
    const top = clusters[0];
    const totalFP = clusters.reduce((s, c) => s + c.sampleCount, 0);
    const roiPct = totalFP > 0 ? (top.sampleCount / totalFP * 100).toFixed(0) : '0';
    console.log(`  Next cluster: ${top.clusterId} ${top.clusterName} (${roiPct}% of FP, ${top.sampleCount} cases)`);
  }

  console.log('═'.repeat(60) + '\n');
}

// ── Comparison against prior report ──
function printComparison(currentStats, priorReportPath) {
  let prior;
  try {
    const resolved = priorReportPath.endsWith('.json') ? priorReportPath : path.join(priorReportPath, 'report.json');
    prior = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  } catch (e) {
    console.error('Cannot read prior report:', e.message);
    return 'SKIP';
  }

  const cur = currentStats.groundTruth;
  const prv = prior.stats?.groundTruth;
  if (!cur || !prv) {
    console.log('\n  No ground truth to compare.');
    return 'SKIP';
  }

  const ce = cur.experimental;
  const pe = prv.experimental;

  // Backward compat: if prior report uses old flat structure, wrap it
  const prvExp = pe.micro ? pe : { micro: { precision: pe.avgPrecision, recall: pe.avgRecall, f1: pe.avgF1 }, macro: { avgF1: pe.avgF1 }, verdictAccuracy: pe.verdictAccuracy };
  const prvMicro = prvExp.micro;
  const prvMacro = prvExp.macro;
  const prvVAcc = prvExp.verdictAccuracy;

  // Default rejection rules (configurable via report.json config)
  const rules = prior.config?.rejectionRules || {
    microF1Decreases: true,
    verdictAccuracyDecreases: true,
    cleanAccuracyDecreases: true,
    familyMaxLossPct: 3,
  };

  const fmt = (v) => (v !== null && v !== undefined ? v.toFixed(3) : 'N/A');
  const fmtPct = (v) => (v !== null && v !== undefined ? (v * 100).toFixed(1) + '%' : 'N/A');
  const delta = (curVal, prvVal) => {
    if (curVal === null || curVal === undefined || prvVal === null || prvVal === undefined) return null;
    return curVal - prvVal;
  };
  const deltaStr = (d) => {
    if (d === null) return '';
    return (d >= 0 ? '+' : '') + d.toFixed(d < 1 && d > -1 ? 4 : 3);
  };
  const deltaPctStr = (curVal, prvVal) => {
    if (curVal === null || prvVal === null || prvVal === 0) return '';
    const d = (curVal - prvVal) / Math.abs(prvVal);
    return (d >= 0 ? '+' : '') + (d * 100).toFixed(1) + '%';
  };

  const metrics = [
    { label: 'Micro Precision', cur: ce.micro.precision, prv: prvMicro.precision },
    { label: 'Micro Recall', cur: ce.micro.recall, prv: prvMicro.recall },
    { label: 'Micro F1', cur: ce.micro.f1, prv: prvMicro.f1 },
    { label: 'Macro F1', cur: ce.macro.avgF1, prv: prvMacro.avgF1 },
    { label: 'Verdict Accuracy', cur: ce.verdictAccuracy, prv: prvVAcc },
    { label: 'Clean Accuracy', cur: cur.cleanAccuracy, prv: prv.cleanAccuracy },
    { label: 'Clean FP Rate', cur: cur.cleanFpRate, prv: prv.cleanFpRate },
  ];

  console.log('\n' + '─'.repeat(60));
  console.log('COMPARISON vs PRIOR BENCHMARK');
  console.log('─'.repeat(60));
  console.log(`  Prior:  ${prior.timestamp}`);
  console.log(`  Current: ${currentStats.groundTruth ? new Date().toISOString() : 'N/A'}`);
  console.log('');
  console.log('  Metric                  Prior    Current  Δ         Δ%');
  console.log('  ' + '─'.repeat(55));
  for (const m of metrics) {
    const d = delta(m.cur, m.prv);
    const dp = deltaPctStr(m.cur, m.prv);
    console.log(`  ${m.label.padEnd(24)} ${fmtPct(m.prv).padStart(7)}  ${fmtPct(m.cur).padStart(7)}  ${deltaStr(d).padStart(8)}  ${dp.padStart(7)}`);
  }

  // byFamily comparison
  const curFamilies = currentStats.byFamily || {};
  const prvFamilies = prior.stats?.byFamily || {};
  const allFamilies = new Set([...Object.keys(curFamilies), ...Object.keys(prvFamilies)]);
  if (allFamilies.size > 0) {
    console.log('');
    console.log('  Family Coverage:');
    console.log('  ' + '─'.repeat(55));
    for (const fam of [...allFamilies].sort()) {
      const cf = curFamilies[fam];
      const pf = prvFamilies[fam];
      const curAcc = cf ? cf.accurate / cf.count : 0;
      const prvAcc = pf ? pf.accurate / pf.count : 0;
      const d = delta(curAcc, prvAcc);
      const dp = deltaPctStr(curAcc, prvAcc);
      console.log(`  ${fam.padEnd(20)} ${fmtPct(prvAcc).padStart(7)}  ${fmtPct(curAcc).padStart(7)}  ${deltaStr(d).padStart(8)}  ${dp.padStart(7)}`);
    }
  }

  // Decision
  let rejected = false;
  const reasons = [];

  if (rules.microF1Decreases && ce.micro.f1 !== null && prvMicro.f1 !== null && ce.micro.f1 < prvMicro.f1) {
    rejected = true;
    reasons.push(`Micro F1 decreased: ${prvMicro.f1.toFixed(3)} → ${ce.micro.f1.toFixed(3)}`);
  }
  if (rules.verdictAccuracyDecreases && ce.verdictAccuracy !== null && prvVAcc !== null && ce.verdictAccuracy < prvVAcc) {
    rejected = true;
    reasons.push(`Verdict accuracy decreased: ${fmtPct(prvVAcc)} → ${fmtPct(ce.verdictAccuracy)}`);
  }
  if (rules.cleanAccuracyDecreases && cur.cleanAccuracy !== null && prv.cleanAccuracy !== null && cur.cleanAccuracy < prv.cleanAccuracy) {
    rejected = true;
    reasons.push(`Clean accuracy decreased: ${fmtPct(prv.cleanAccuracy)} → ${fmtPct(cur.cleanAccuracy)}`);
  }
  if (rules.familyMaxLossPct > 0) {
    for (const fam of allFamilies) {
      const cf = curFamilies[fam];
      const pf = prvFamilies[fam];
      if (cf && pf) {
        const curAcc = cf.accurate / cf.count;
        const prvAcc = pf.accurate / pf.count;
        if (curAcc < prvAcc && (prvAcc - curAcc) > (rules.familyMaxLossPct / 100)) {
          rejected = true;
          reasons.push(`Family "${fam}" lost >${rules.familyMaxLossPct}%: ${fmtPct(prvAcc)} → ${fmtPct(curAcc)}`);
        }
      }
    }
  }

  console.log('');
  const decision = rejected ? 'REJECTED' : 'ACCEPTED';
  console.log(`  Decision: ${decision}`);
  if (reasons.length > 0) {
    console.log('  Reason(s):');
    for (const r of reasons) console.log(`    • ${r}`);
  }
  console.log('─'.repeat(60) + '\n');

  return decision;
}

async function run() {
  // Load manifest
  if (!fs.existsSync(MANIFEST_PATH)) {
    console.error('PR Zoo not found. Run node scripts/pr_zoo_collector.js first.');
    process.exit(1);
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  let entries = manifest.entries || [];

  if (sampleCount > 0 && sampleCount < entries.length) {
    // Stratified: take evenly across repos
    const byRepo = {};
    for (const e of entries) {
      if (!byRepo[e.repo]) byRepo[e.repo] = [];
      byRepo[e.repo].push(e);
    }
    const perRepo = Math.max(1, Math.floor(sampleCount / Object.keys(byRepo).length));
    entries = [];
    for (const [repo, repoEntries] of Object.entries(byRepo)) {
      entries.push(...repoEntries.slice(0, perRepo));
    }
    entries = entries.slice(0, sampleCount);
  }

  console.log('═'.repeat(60));
  console.log('BENCHMARK RUNNER v1.0');
  console.log(`Dataset: ${entries.length} samples from PR Zoo`);
  console.log(`Mode: ${isWarm ? 'WARM cache' : 'COLD cache'}`);
  console.log(`Budgets: ${useBudgets ? 'ENFORCED' : 'disabled'}`);
  console.log(`Phase breakdown: ${phaseBreakdown ? 'enabled' : 'summary only'}`);
  console.log(`Cache dir: ${CACHE_DIR}`);
  console.log('═'.repeat(60));

  // Run all samples
  const results = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const r = runSample(entry, i, entries.length);
    if (r) {
      results.push(r);
      const flag = r.diverged ? ' ⚠' : '';
      console.log(`  [${i + 1}/${entries.length}] ${entry.repo} #${entry.pr} — ${r.baseline.verdict}→${r.experimental.verdict} ${r.phases._total.toFixed(1)}ms ${r.memory.peakDeltaMb}MB${flag}`);
    } else {
      console.log(`  [${i + 1}/${entries.length}] ${entry.repo} #${entry.pr} — SKIP (no patch file)`);
    }
  }

  // Stats
  const stats = computeStats(results);
  if (!stats) {
    console.log('\nNo valid results.');
    process.exit(1);
  }

  // Budgets
  let budgetsPassed = true;
  if (useBudgets) {
    const budgetResult = checkBudgets(results);
    budgetsPassed = budgetResult.passed;
    if (!budgetsPassed) {
      console.log('\n⚠ BUDGET FAILURES:');
      for (const f of budgetResult.failures) {
        console.log(`  ${f.sample}: ${f.metric} = ${f.value.toFixed(1)} (budget: ${f.budget})`);
      }
    }
  }

  // Divergences
  const divergencesCount = saveDivergences(results);

  // Save report
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const reportDir = path.join(BENCHMARK_DIR, ts);
  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });

  // Full report
  const gtSummary = stats.groundTruth
    ? {
        samplesWithGT: stats.groundTruth.samplesWithGT,
        baseline: stats.groundTruth.baseline,
        experimental: stats.groundTruth.experimental,
        bySource: stats.groundTruth.bySource,
      }
    : null;

  const report = {
    timestamp: new Date().toISOString(),
    config: {
      samples: entries.length,
      warm: isWarm,
      budgets: useBudgets,
      phaseBreakdown,
      nodeVersion: process.version,
      platform: process.platform,
    },
    stats,
    groundTruth: gtSummary,
    budgets: useBudgets
      ? { passed: budgetsPassed, failures: checkBudgets(results).failures }
      : { passed: true, failures: [] },
    divergences: divergencesCount || 0,
  };
  fs.writeFileSync(path.join(reportDir, 'report.json'), JSON.stringify(report, null, 2));

  // Results CSV (one row per sample)
  const csvHeader = 'id,repo,pr,family,technique,variant,baselineVerdict,baselineRisk,baselineFindings,experimentalVerdict,experimentalRisk,experimentalFindings,verdictChange,riskDelta,findingsAdded,findingsRemoved,capsAdded,capsRemoved,timeMs,memoryMb,qualityScore,gtSource,gtPrecision,gtRecall,gtF1,gtVerdictAccurate,failureReason,experimentalConfidence,experimentalMaxConfidence\n';
  const csvRows = results
    .filter(Boolean)
    .map((r) => {
      const c = r.comparison || {};
      const gtExp = r.groundTruth?.experimental || {};
      return [
        r.id,
        r.repo,
        r.pr,
        r.taxonomy?.family || '',
        r.taxonomy?.technique || '',
        r.variant !== null ? r.variant : '',
        r.baseline.verdict,
        r.baseline.riskScore,
        r.baseline.findings,
        r.experimental.verdict,
        r.experimental.riskScore,
        r.experimental.findings,
        c.verdictChange || 'N/A',
        c.riskScoreDelta ?? 0,
        c.findingDiff?.addedCount || 0,
        c.findingDiff?.removedCount || 0,
        c.capabilityDiff?.addedCount || 0,
        c.capabilityDiff?.removedCount || 0,
        r.phases._total.toFixed(1),
        r.memory.peakDeltaMb.toFixed(1),
        r.qualityScore,
        r.expectedSource || '',
        gtExp.findingMetrics?.precision ?? '',
        gtExp.findingMetrics?.recall ?? '',
        gtExp.findingMetrics?.f1 ?? '',
        gtExp.verdictMatch?.accurate ?? '',
        gtExp.failureReason ?? '',
        r.experimental.decisionConfidence ?? '',
        r.experimental.maxConfidence ?? '',
      ].join(',');
    })
    .join('\n');
  fs.writeFileSync(path.join(reportDir, 'results.csv'), csvHeader + csvRows + '\n');

  // Samples JSON — per-sample details for post-hoc analysis (clustering, etc.)
  const samplesDetail = results
    .filter(Boolean)
    .map(r => ({
      id: r.id,
      repo: r.repo,
      pr: r.pr,
      taxonomy: r.taxonomy,
      variant: r.variant,
      baselineVerdict: r.baseline.verdict,
      experimentalVerdict: r.experimental.verdict,
      experimentalFindings: r.experimental.findings,
      experimentalFindingRules: r.experimental.findingRules,
      experimentalCapabilities: r.experimental.capabilities,
      experimentalConfidence: r.experimental.decisionConfidence,
      gtExpectedVerdict: r.groundTruth?.expected?.verdict || null,
      gtVerdictAccurate: r.groundTruth?.experimental?.verdictMatch?.accurate ?? null,
      gtFailureReason: r.groundTruth?.experimental?.failureReason ?? null,
      gtExpectedSource: r.expectedSource,
      gtPrecision: r.groundTruth?.experimental?.findingMetrics?.precision ?? null,
      gtRecall: r.groundTruth?.experimental?.findingMetrics?.recall ?? null,
      qualityScore: r.qualityScore,
      diverged: r.diverged,
    }));
  fs.writeFileSync(path.join(reportDir, 'samples.json'), JSON.stringify(samplesDetail, null, 2));

  // Cluster analysis (FP clusters)
  const clusters = analyzeClusters(results);
  if (clusters.length > 0) {
    fs.writeFileSync(path.join(reportDir, 'clusters.json'), JSON.stringify(clusters, null, 2));
  }

  // Phase breakdown CSV (if enabled)
  if (phaseBreakdown) {
    const phaseHeader = 'id,repo,pr,total,parse,normalize,graph,evidence\n';
    const phaseRows = results
      .filter(Boolean)
      .map((r) => {
        const p = r.phases;
        return [r.id, r.repo, r.pr, p._total.toFixed(2), (p.parse || 0).toFixed(2), (p.normalize || 0).toFixed(2), (p.graph || 0).toFixed(2), (p.evidence || 0).toFixed(2)].join(',');
      })
      .join('\n');
    fs.writeFileSync(path.join(reportDir, 'phases.csv'), phaseHeader + phaseRows + '\n');
  }

  // History
  appendHistory(stats, budgetsPassed, divergencesCount || 0);

  // Console summary
  console.log('\n' + '═'.repeat(60));
  console.log('RESULTS');
  console.log(`  Samples: ${stats.samples}`);
  console.log(`  Time: avg=${stats.time.avg.toFixed(1)}ms p50=${stats.time.p50}ms p95=${stats.time.p95}ms p99=${stats.time.p99}ms`);
  console.log(`  Memory: avg=${stats.memory.avg.toFixed(1)}MB peak=${stats.memory.max.toFixed(1)}MB`);
  console.log(`  Quality: avg=${stats.quality.avg.toFixed(1)}/${10} min=${stats.quality.min} max=${stats.quality.max}`);
  console.log(`  Divergences: ${stats.divergences.total} (${stats.divergences.pct}% of samples)`);
  console.log(`    ESCALATED: ${stats.divergences.escalated}`);
  console.log(`    DEESCALATED: ${stats.divergences.deescaped}`);
  if (stats.groundTruth) {
    const b = stats.groundTruth.baseline;
    const e = stats.groundTruth.experimental;
    console.log(`  Ground Truth (${stats.groundTruth.samplesWithGT} samples):`);
    console.log(`    Baseline: micro P=${b.micro.precision.toFixed(3)} R=${b.micro.recall.toFixed(3)} F1=${b.micro.f1.toFixed(3)}  macro F1=${b.macro.avgF1.toFixed(3)}  VAcc=${(b.verdictAccuracy * 100).toFixed(1)}%`);
    console.log(`    Experimental: micro P=${e.micro.precision.toFixed(3)} R=${e.micro.recall.toFixed(3)} F1=${e.micro.f1.toFixed(3)}  macro F1=${e.macro.avgF1.toFixed(3)}  VAcc=${(e.verdictAccuracy * 100).toFixed(1)}%`);
    if (stats.groundTruth.cleanAccuracy !== null) {
      console.log(`    Clean: accuracy=${(stats.groundTruth.cleanAccuracy * 100).toFixed(1)}%  FP rate=${(stats.groundTruth.cleanFpRate * 100).toFixed(1)}%  (${stats.groundTruth.cleanCount} samples)`);
    }
  }
  console.log(`  Budgets: ${budgetsPassed ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`\n  Report: ${reportDir}`);
  console.log(`  History: ${HISTORY_PATH}`);
  console.log(`  Interesting cases: ${INTERESTING_DIR}`);

  // Comparison against prior report
  let compareDecision = null;
  if (compareToPath) {
    compareDecision = printComparison(stats, compareToPath);
  }

  // Dashboard
  const fpClusters = clusters || [];
  printDashboard(stats, fpClusters, compareDecision, compareToPath);

  console.log('═'.repeat(60));

  // Exit with code for CI gates
  if (useBudgets && !budgetsPassed) process.exit(1);
  if (compareDecision === 'REJECTED') process.exit(2);
}

run().catch(console.error);
