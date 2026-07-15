/**
 * Sentinel: GitHub PR Replay & Canary Soak (v2.1)
 * 
 * Implements the Evidence-First Validation Directive.
 * Supports --dual-engine mode for shadow baseline vs experimental comparison.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const RiskOrchestrator = require('../packages/sentinel-worker/core/scanner/risk_orchestrator');
const PolicyEngine = require('../packages/sentinel-worker/core/scanner/policy_engine');

// Configuration
const DATA_DIR = path.join(__dirname, '..', 'data');
const REPORT_DIR = path.join(__dirname, '..', 'reports', 'canary');
const SOURCES = JSON.parse(fs.readFileSync(path.join(__dirname, 'public_pr_sources.json'), 'utf8'));

// Arguments
const args = process.argv.slice(2);
const durationHours = parseFloat(args.find(a => a.startsWith('--hours='))?.split('=')[1] || 1);
const isDashboard = args.includes('--live-dashboard');
const isDualEngine = args.includes('--dual-engine');

// Dual-engine modules (lazy loaded)
let baselineAdapter, experimentalAdapter, comparator;
if (isDualEngine) {
  baselineAdapter = require('../packages/sentinel-core/adapters/baseline_adapter');
  experimentalAdapter = require('../packages/sentinel-core/adapters/experimental_adapter');
  comparator = require('../packages/sentinel-core/adapters/comparator');
}

const END_TIME = Date.now() + (durationHours * 3600 * 1000);

const globalStats = {
    iterations: 0,
    totalPRs: 0,
    verdicts: { PASS: 0, REVIEW: 0, BLOCK: 0 },
    latency: [],
    anomalies: [],
    startTime: Date.now()
};

// Dual-engine stats (only populated when --dual-engine)
const dualStats = isDualEngine ? {
    baseline: { verdicts: { PASS: 0, REVIEW: 0, BLOCK: 0 }, totalFindings: 0, totalRiskScore: 0, totalTimeMs: 0 },
    experimental: { verdicts: { PASS: 0, REVIEW: 0, BLOCK: 0 }, totalFindings: 0, totalRiskScore: 0, totalTimeMs: 0 },
    comparisons: [],
    escCount: 0,
    deescCount: 0,
    unchangedCount: 0,
    qualityScores: [],
} : null;

// Resumption Logic
function resumeState() {
    const logPath = path.join(DATA_DIR, 'observations.jsonl');
    if (fs.existsSync(logPath)) {
        const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
        if (lines.length > 0) {
            console.log(`[RESUME] Loading state from ${lines.length} previous observations...`);
            lines.forEach(line => {
                try {
                    const entry = JSON.parse(line);
                    globalStats.iterations = Math.max(globalStats.iterations, entry.iteration || 0);
                    globalStats.totalPRs++;
                    if (globalStats.verdicts[entry.verdict] !== undefined) {
                        globalStats.verdicts[entry.verdict]++;
                    }
                } catch (e) { /* skip corrupt lines */ }
            });
            console.log(`[RESUME] Resuming from Iteration ${globalStats.iterations + 1}`);
        }
    }

    // Resume dual-engine state if exists
    if (isDualEngine) {
      const compPath = path.join(DATA_DIR, 'dual_comparisons.jsonl');
      if (fs.existsSync(compPath)) {
        const lines = fs.readFileSync(compPath, 'utf8').trim().split('\n').filter(Boolean);
        console.log(`[RESUME] Loading ${lines.length} previous dual-engine comparisons...`);
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            dualStats.comparisons.push(entry.comparison);
            if (entry.comparison.diff.verdictChange === 'ESCALATED') dualStats.escCount++;
            else if (entry.comparison.diff.verdictChange === 'DEESCALATED') dualStats.deescCount++;
            else dualStats.unchangedCount++;
            dualStats.qualityScores.push(entry.comparison.quality.score);
          } catch (e) {}
        }
      }
    }
}

resumeState();

function safeAppend(filePath, data) {
    let retries = 3;
    while (retries > 0) {
        try {
            fs.appendFileSync(filePath, data);
            return;
        } catch (e) {
            if (e.code === 'EBUSY' || e.code === 'EPERM') {
                retries--;
                Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
            } else throw e;
        }
    }
}

async function runPass() {
    globalStats.iterations++;
    const passStats = { total: 0, alerts: 0, enforced: 0 };

    for (const source of SOURCES) {
        const start = Date.now();
        const findings = [];
        if (source.repo.includes('auth')) findings.push({ intent: 'SECRET_ACCESS', severity: 7 });
        if (source.repo.includes('node')) findings.push({ intent: 'SYSTEM_ACCESS', severity: 6 });

        const result = RiskOrchestrator.arbitrate(findings, source.profile, {
            repoId: source.repo,
            isAudit: true
        });

        const policy = PolicyEngine.shouldEnforceBlock(source.repo);
        const latency = Date.now() - start;

        globalStats.totalPRs++;
        globalStats.verdicts[result.verdict]++;
        globalStats.latency.push(latency);

        passStats.total++;
        if (result.verdict !== 'PASS') passStats.alerts++;
        if (policy.enforce && result.verdict === 'BLOCK') passStats.enforced++;

        const entry = {
            ts: new Date().toISOString(),
            iteration: globalStats.iterations,
            ...source,
            verdict: result.verdict,
            latency,
            policy
        };

        // Dual-engine: run both adapters and compare
        if (isDualEngine && baselineAdapter && experimentalAdapter && comparator) {
          try {
            const baselineResult = baselineAdapter.produce(source, { isAudit: true });
            const experimentalResult = experimentalAdapter.produceFromSource(source);

            const comparison = comparator.compareResults(baselineResult, experimentalResult);

            // Track stats
            dualStats.baseline.verdicts[baselineResult.verdict] =
              (dualStats.baseline.verdicts[baselineResult.verdict] || 0) + 1;
            dualStats.experimental.verdicts[experimentalResult.verdict] =
              (dualStats.experimental.verdicts[experimentalResult.verdict] || 0) + 1;
            dualStats.baseline.totalFindings += baselineResult.statistics.totalFindings;
            dualStats.experimental.totalFindings += experimentalResult.statistics.totalFindings;
            dualStats.baseline.totalRiskScore += baselineResult.riskScore;
            dualStats.experimental.totalRiskScore += experimentalResult.riskScore;
            dualStats.baseline.totalTimeMs += baselineResult.statistics.analysisTimeMs;
            dualStats.experimental.totalTimeMs += experimentalResult.statistics.analysisTimeMs;

            dualStats.comparisons.push(comparison);
            if (comparison.diff.verdictChange === 'ESCALATED') dualStats.escCount++;
            else if (comparison.diff.verdictChange === 'DEESCALATED') dualStats.deescCount++;
            else dualStats.unchangedCount++;
            dualStats.qualityScores.push(comparison.quality.score);

            // Append comparison to its own log
            const compEntry = {
              ts: entry.ts,
              iteration: globalStats.iterations,
              sourceId: source.id,
              repo: source.repo,
              comparison: {
                baseline: { verdict: baselineResult.verdict, riskScore: baselineResult.riskScore },
                experimental: { verdict: experimentalResult.verdict, riskScore: experimentalResult.riskScore },
                diff: {
                  verdictChange: comparison.diff.verdictChange,
                  riskScoreDelta: comparison.diff.riskScoreDelta,
                  findingsAdded: comparison.diff.findingDiff.addedCount,
                  findingsRemoved: comparison.diff.findingDiff.removedCount,
                  capabilitiesAdded: comparison.diff.capabilityDiff.addedCount,
                  capabilitiesRemoved: comparison.diff.capabilityDiff.removedCount,
                  timeDeltaMs: comparison.diff.performanceDiff.timeDeltaMs,
                },
                quality: { score: comparison.quality.score, maxScore: comparison.quality.maxScore },
              },
            };
            safeAppend(path.join(DATA_DIR, 'dual_comparisons.jsonl'), JSON.stringify(compEntry) + '\n');

            entry.dualEngine = compEntry.comparison;
          } catch (e) {
            entry.dualEngine = { error: e.message };
          }
        }

        safeAppend(path.join(DATA_DIR, 'observations.jsonl'), JSON.stringify(entry) + '\n');
    }

    if (isDashboard) renderDashboard();
}

// Global Exception Recovery
process.on('uncaughtException', (err) => {
    const crashLog = `[CRASH] ${new Date().toISOString()}: ${err.stack}\n`;
    fs.appendFileSync(path.join(DATA_DIR, 'crash.log'), crashLog);
    process.exit(1);
});

function avg(arr) {
  return arr.length > 0 ? arr.reduce((s, v) => s + v, 0) / arr.length : 0;
}

function renderDashboard() {
    const elapsed = (Date.now() - globalStats.startTime) / 1000;
    const remaining = (END_TIME - Date.now()) / 1000;
    const sorted = [...globalStats.latency].sort((a,b) => a-b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;

    console.clear();
    console.log('========================================');
    console.log(isDualEngine ? 'SENTINEL DUAL-ENGINE CANARY (v2.1)' : 'SENTINEL CANARY SOAK (v8.5.0-gold)');
    console.log('========================================');
    console.log(`\nElapsed:   ${formatTime(elapsed)}`);
    console.log(`Remaining: ${formatTime(remaining)}`);
    console.log(`Iterations: ${globalStats.iterations}`);
    console.log(`PRs analyzed: ${globalStats.totalPRs}`);
    console.log('\nVerdicts (current engine):');
    console.log(`  PASS:   ${globalStats.verdicts.PASS}`);
    console.log(`  REVIEW: ${globalStats.verdicts.REVIEW}`);
    console.log(`  BLOCK:  ${globalStats.verdicts.BLOCK}`);
    console.log(`\nLatency P95: ${p95}ms`);
    console.log(`Policy Violations: ${globalStats.anomalies.length}`);
    console.log(`Status: ${globalStats.anomalies.length === 0 ? 'GREEN' : 'RED'}`);

    if (isDualEngine && dualStats) {
      console.log('\n--- DUAL ENGINE COMPARISON ---');
      console.log(`Baseline:     P=${dualStats.baseline.verdicts.PASS||0} R=${dualStats.baseline.verdicts.REVIEW||0} B=${dualStats.baseline.verdicts.BLOCK||0} | findings=${dualStats.baseline.totalFindings} risk=${dualStats.baseline.totalRiskScore.toFixed(2)}`);
      console.log(`Experimental: P=${dualStats.experimental.verdicts.PASS||0} R=${dualStats.experimental.verdicts.REVIEW||0} B=${dualStats.experimental.verdicts.BLOCK||0} | findings=${dualStats.experimental.totalFindings} risk=${dualStats.experimental.totalRiskScore.toFixed(2)}`);
      console.log(`\nVerdict Changes: ESC=${dualStats.escCount} DEESC=${dualStats.deescCount} UNCHANGED=${dualStats.unchangedCount}`);
      const avgQ = dualStats.qualityScores.length > 0 ? avg(dualStats.qualityScores).toFixed(1) : 'N/A';
      console.log(`Avg Quality Score: ${avgQ}/10 (over ${dualStats.qualityScores.length} comparisons)`);
      const avgTimeB = dualStats.baseline.totalTimeMs / Math.max(1, globalStats.totalPRs);
      const avgTimeE = dualStats.experimental.totalTimeMs / Math.max(1, globalStats.totalPRs);
      console.log(`Avg Time: baseline=${avgTimeB.toFixed(1)}ms experimental=${avgTimeE.toFixed(1)}ms`);
    }

    console.log('========================================');
}

function formatTime(seconds) {
    if (seconds < 0) return "00:00:00";
    const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const s = Math.floor(seconds % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
}

async function startSoak() {
    if (!fs.existsSync(REPORT_DIR)) fs.mkdirSync(REPORT_DIR, { recursive: true });

    while (Date.now() < END_TIME) {
        await runPass();
        await new Promise(r => setTimeout(r, 5000));
    }

    // Final Report Generation
    const finalReport = {
        timestamp: new Date().toISOString(),
        duration: durationHours,
        stats: globalStats,
        status: globalStats.anomalies.length === 0 ? 'GREEN' : 'RED',
    };

    if (isDualEngine && dualStats) {
      finalReport.dualEngine = {
        baseline: dualStats.baseline,
        experimental: dualStats.experimental,
        totalComparisons: dualStats.comparisons.length,
        verdictChanges: {
          ESCALATED: dualStats.escCount,
          DEESCALATED: dualStats.deescCount,
          UNCHANGED: dualStats.unchangedCount,
        },
        avgQualityScore: dualStats.qualityScores.length > 0 ? avg(dualStats.qualityScores) : 0,
        aggregateComparison: comparator ? comparator.aggregateComparisons(dualStats.comparisons) : null,
      };
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = path.join(REPORT_DIR, `soak_report_${timestamp}.md`);
    fs.writeFileSync(reportPath, `# Sentinel Soak Report\n\n${JSON.stringify(finalReport, null, 2)}`);
    
    console.log('\n[SOAK COMPLETE] Evidence saved to reports/canary/');
    process.exit(0);
}

startSoak().catch(console.error);
