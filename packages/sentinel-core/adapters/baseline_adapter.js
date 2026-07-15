'use strict';

/**
 * Baseline Adapter — wraps the existing RiskOrchestrator pipeline
 * into the canonical EngineResult contract.
 *
 * This is what the current canary soak uses:
 *   source.repo → synthetic findings → RiskOrchestrator.arbitrate() → verdict
 *
 * It does NOT run the new evasion/normalizer/IR layers.
 */

const RiskOrchestrator = require('../scanner/risk_orchestrator');
const PolicyEngine = require('../scanner/policy_engine');
const { createMutableEngineResult } = require('../contracts/engine_result');

const REPO_INTENT_MAP = {
  'auth': { intent: 'SECRET_ACCESS', severity: 7, type: 'credential_access' },
  'node': { intent: 'SYSTEM_ACCESS', severity: 6, type: 'system_access' },
  'express': { intent: 'MIDDLEWARE_ACCESS', severity: 5, type: 'network_access' },
  'next': { intent: 'FRAMEWORK_ACCESS', severity: 3, type: 'code_execution' },
  'react': { intent: 'UI_ACCESS', severity: 2, type: 'information_disclosure' },
  'lodash': { intent: 'LIBRARY_PATCH', severity: 4, type: 'supply_chain' },
  'npm': { intent: 'PACKAGE_ACCESS', severity: 6, type: 'supply_chain' },
  'webpack': { intent: 'BUILD_ACCESS', severity: 3, type: 'build_pipeline' },
  'jest': { intent: 'TEST_ACCESS', severity: 2, type: 'test_code' },
  'typescript': { intent: 'COMPILER_ACCESS', severity: 3, type: 'build_pipeline' },
};

const DEFAULT_INTENT = { intent: 'UNKNOWN', severity: 1, type: 'generic' };

function findingsFromSource(source) {
  const repoLower = (source.repo || '').toLowerCase();
  const findings = [];

  for (const [keyword, mapping] of Object.entries(REPO_INTENT_MAP)) {
    if (repoLower.includes(keyword)) {
      findings.push({
        type: mapping.type,
        severity: mapping.severity >= 7 ? 'CRITICAL' : mapping.severity >= 5 ? 'HIGH' : 'MEDIUM',
        riskLevel: mapping.severity,
        message: `${mapping.intent} detected in ${source.repo}`,
        file: `${source.repo}/pr_${source.pr}`,
        sourceEngine: 'BASELINE_ORCHESTRATOR',
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      type: 'generic',
      severity: 'INFO',
      riskLevel: 0,
      message: `No specific pattern matched for ${source.repo}`,
      file: `${source.repo}/pr_${source.pr}`,
      sourceEngine: 'BASELINE_ORCHESTRATOR',
    });
  }

  return findings;
}

function produce(source, options = {}) {
  const startTime = Date.now();

  const findings = findingsFromSource(source);

  const result = RiskOrchestrator.arbitrate(findings, source.profile || 'default', {
    repoId: source.repo,
    isAudit: options.isAudit !== false,
  });

  const latencyMs = Date.now() - startTime;

  const policy = PolicyEngine.shouldEnforceBlock(source.repo);

  const engineResult = createMutableEngineResult({
    engineName: 'baseline',
    engineVersion: '8.5.0-gold',
    layers: ['synthetic_findings', 'risk_orchestrator', 'policy_engine'],
    scanId: `baseline_${source.id || source.repo}_${source.pr}`,
    findings: findings.map((f, i) => ({
      ...f,
      id: `baseline_${source.id || 'pr'}_${i}`,
    })),
    riskScore: result.score || 0,
    verdict: result.decision || 'PASS',
    riskBand: result.riskBand?.name || 'NEGLIGIBLE',
    decisionConfidence: result.decisionConfidence || 1.0,
    capabilities: findings.map(f => f.type),
    statistics: {
      analysisTimeMs: latencyMs,
      memoryBytes: 0,
      filesAnalyzed: 1,
      filesWithFindings: findings.filter(f => f.riskLevel > 0).length > 0 ? 1 : 0,
    },
    metadata: {
      policy: policy || undefined,
      source: source,
      rationale: result.rationale || undefined,
      traceId: result.traceId || undefined,
    },
  });

  return engineResult;
}

module.exports = { produce, findingsFromSource, REPO_INTENT_MAP };
