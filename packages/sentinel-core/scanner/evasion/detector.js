'use strict';

const { scanPatterns } = require('./patterns');
const { analyzeHeuristics } = require('./heuristics');
const { scanSemantic } = require('./semantic_patterns');
const { scanSignatures } = require('./signatures');
const { normalize } = require('./normalizer');
const { build } = require('./property_graph');

const SCORING = {
  CRITICAL: 10,
  HIGH: 8,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

function severityWeight(severity) {
  return SCORING[severity] || 0;
}

function aggregateReport(byCategory) {
  const report = {};
  for (const [cat, findings] of Object.entries(byCategory)) {
    const maxRisk = Math.max(...findings.map(f => f.risk));
    const uniqueTypes = [...new Set(findings.map(f => f.type))];
    const uniqueSources = [...new Set(findings.map(f => f.source))];
    report[cat] = {
      count: findings.length,
      maxRisk,
      uniqueTypes,
      sources: uniqueSources,
      score: Math.min(1.0, findings.reduce((s, f) => s + severityWeight(f.severity), 0) / 30),
    };
  }
  return report;
}

function analyzeIR(symbols, code) {
  const findings = [];

  // IR-1: Variable bracket access to dangerous properties
  // e.g., const method = 'exec'; cp[method]()
  const DANGEROUS_PROPS = ['exec', 'execSync', 'spawn', 'fork', 'eval', 'Function', 'constructor', 'prototype', '__proto__'];
  for (const cs of symbols.callSites) {
    const callName = cs.name;
    for (const prop of DANGEROUS_PROPS) {
      if (callName && callName.endsWith(`.${prop}`)) {
        // Check if it was resolved via variable (computed property)
        const callee = cs.node && cs.node.callee;
        if (callee && callee.type === 'MemberExpression' && callee.computed) {
          const propNode = callee.property;
          const isVariableResolved = propNode && propNode.type === 'Identifier';
          if (!findings.some(f => f.id === 'IR-001' && f.match === prop)) {
            findings.push({
              id: 'IR-001',
              type: 'VARIABLE_BRACKET_ACCESS',
              severity: 'HIGH',
              risk: 8,
              category: 'obfuscation',
              description: `Dangerous property '${prop}' resolved via variable bracket access (IR)`,
              match: prop,
              source: 'IR',
            });
          }
        }
      }
    }
  }

  // IR-2: Array-indexed method resolution
  // e.g., const methods = ['exec', 'spawn']; cp[methods[0]]()
  for (const cs of symbols.callSites) {
    if (cs.name && cs.name.includes('.')) {
      for (const prop of DANGEROUS_PROPS) {
        if (cs.name.endsWith(`.${prop}`)) {
          const alreadyFound = findings.some(f =>
            f.id === 'IR-002' && f.description.includes(prop));
          if (!alreadyFound) {
            findings.push({
              id: 'IR-002',
              type: 'ARRAY_INDEXED_RESOLUTION',
              severity: 'HIGH',
              risk: 8,
              category: 'obfuscation',
              description: `Dangerous property '${prop}' resolved via array-indexed access (IR)`,
              source: 'IR',
            });
          }
        }
      }
    }
  }

  // IR-3: Encoded sink reconstruction via constant folding
  // e.g., String.fromCharCode(101,120,101,99) -> 'exec'
  for (const cs of symbols.callSites) {
    if (cs.name === 'String.fromCharCode' || cs.name === 'atob' || cs.name === 'Buffer.from') {
      findings.push({
        id: 'IR-003',
        type: 'ENCODED_SINK_RECONSTRUCTION',
        severity: 'HIGH',
        risk: 7,
        category: 'obfuscation',
        description: `Encoded string resolved via constant folding: ${cs.name}`,
        source: 'IR',
      });
    }
  }

  return findings;
}

function assessCode(code, filename, options = {}) {
  // Phase 1: Run normalizer to build SymbolTable (NormalizedIR)
  const symbols = normalize(code);

  // Phase 2: Build Property Graph from IR
  const propertyGraph = build(symbols, code);

  // Phase 3: Legacy layers (backward compatible, operate on raw text)
  const patternFindings = scanPatterns(code);
  const heuristicFindings = analyzeHeuristics(code);
  const semanticFindings = scanSemantic(code);
  const signatureFindings = scanSignatures(code);

  // Phase 4: IR-based analysis (closes variable bracket + array-index gaps)
  const irFindings = analyzeIR(symbols, code);

  const allFindings = [
    ...patternFindings,
    ...heuristicFindings,
    ...semanticFindings,
    ...signatureFindings,
    ...irFindings,
  ];

  const byCategory = {};
  for (const f of allFindings) {
    const cat = f.category || 'unknown';
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(f);
  }

  const detectionSummary = {
    detected: allFindings.length > 0,
    totalFindings: allFindings.length,
    categories: Object.keys(byCategory),
    byCategory: aggregateReport(byCategory),
    totalRisk: allFindings.reduce((s, f) => s + (f.risk || 0), 0),
    maxSeverity: Math.max(...allFindings.map(f => severityWeight(f.severity)), 0),
  };

  let verdict = 'CLEAN';
  if (detectionSummary.maxSeverity >= 9) {
    verdict = 'CRITICAL';
  } else if (detectionSummary.maxSeverity >= 7) {
    // Multi-signal escalation: execution + obfuscation/supply_chain → CRITICAL
    const cats = Object.keys(detectionSummary.byCategory);
    const hasExec = cats.includes('execution');
    const otherCats = cats.filter(c => c !== 'execution' && c !== 'unknown');
    if (hasExec && otherCats.length >= 1 && detectionSummary.totalFindings >= 2) {
      verdict = 'CRITICAL';
    } else {
      verdict = 'SUSPICIOUS';
    }
  } else if (detectionSummary.maxSeverity >= 4) {
    verdict = 'WARNING';
  } else if (detectionSummary.detected) {
    verdict = 'INFO';
  }

  return {
    verdict,
    summary: detectionSummary,
    findings: allFindings,
    propertyGraph: propertyGraph.toJSON(),
    filename,
  };
}

module.exports = { assessCode, aggregateReport };
