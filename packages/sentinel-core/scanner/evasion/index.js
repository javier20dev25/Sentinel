'use strict';

/**
 * Sentinel Evasion Detector
 *
 * Multi-layer static analysis for code evasion techniques.
 * Derived from 30-seed GA campaigns across 54,472 evaluations.
 *
 * Layers:
 *   1. PATTERN    — 28 deterministic regex patterns (10 categories)
 *   2. HEURISTIC  — 12 heuristic rules (entropy, escape density, etc.)
 *   3. SEMANTIC   — 10 semantic/AST-level patterns
 *   4. SIGNATURE  — 7 known evasion signatures from campaigns
 *
 * Integration with scanFile:
 *   const evasion = require('./evasion');
 *   const result = evasion.analyze(content, filename);
 *   if (result.verdict !== 'CLEAN') {
 *     results.evasion = result;
 *     results.alerts.push(...result.findings.map(f => ({ ... })));
 *   }
 */

const { assessCode, aggregateReport } = require('./detector');
const { shannonEntropy } = require('./heuristics');
const knowledgeBase = require('./knowledge_base.json');

function analyze(content, filename, options = {}) {
  if (!content || typeof content !== 'string') {
    return { verdict: 'CLEAN', summary: { detected: false, totalFindings: 0 }, findings: [], filename };
  }
  return assessCode(content, filename, options);
}

module.exports = {
  analyze,
  assessCode,
  aggregateReport,
  shannonEntropy,
  knowledgeBase,
};
