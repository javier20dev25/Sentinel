'use strict';

const { analyze } = require('./index');
const { classifyFindings, groupByPrinciple, coverageGaps } = require('./taxonomy');
const knowledgeBase = require('./knowledge_base.json');

const TECHNIQUE_INDEX = new Map();
for (const tech of knowledgeBase.techniques) {
  TECHNIQUE_INDEX.set(tech.id, tech);
}

const PRINCIPLE_INDEX = new Map();
for (const taxon of knowledgeBase.taxonomy) {
  PRINCIPLE_INDEX.set(taxon.id, taxon);
}

function comparePrincipleConfidence(taxon, scanResult) {
  let newTechniques = 0;
  const totalTechniques = taxon.techniqueIds.length;
  for (const techId of taxon.techniqueIds) {
    const detected = scanResult.findings.some(f => f.id === techId);
    if (!detected) newTechniques++;
  }
  const evasionRate = newTechniques / Math.max(1, totalTechniques);
  return {
    principle: taxon.principle,
    totalTechniques,
    detectedInScan: totalTechniques - newTechniques,
    missed: newTechniques,
    evasionRate,
    confidence: 1.0 - evasionRate,
  };
}

function generateReport(campaignId, codes, results) {
  const allFindings = results.flatMap(r => r.findings);
  const classified = classifyFindings(allFindings);
  const byPrinciple = groupByPrinciple(classified);

  const discoveredTechniques = [];
  const discoveredSet = new Set();
  for (const item of classified) {
    if (item.technique) {
      const key = item.technique.id;
      if (!discoveredSet.has(key)) {
        discoveredSet.add(key);
        discoveredTechniques.push({
          id: item.technique.id,
          name: item.technique.name,
          category: item.technique.category,
          principle: item.principle ? item.principle.principle : 'unknown',
          detectionLayers: item.technique.detectionLayers,
          avgEvasion: item.technique.avgEvasion,
          rule: item.technique.rule,
          regressionTest: item.technique.regressionTest,
        });
      }
    }
  }

  const principalConfidence = [];
  for (const taxon of knowledgeBase.taxonomy) {
    const conf = comparePrincipleConfidence(taxon, { findings: allFindings });
    principalConfidence.push(conf);
  }

  const evasionCategories = {};
  for (const result of results) {
    if (result.verdict !== 'CLEAN') {
      for (const cat of result.summary.categories) {
        evasionCategories[cat] = (evasionCategories[cat] || 0) + 1;
      }
    }
  }

  const suggestedRules = discoveredTechniques
    .filter(t => t.detectionLayers.includes('patterns'))
    .map(t => ({ type: 'deterministic', name: t.regressionTest, techniqueId: t.id, principle: t.principle }));

  const suggestedHeuristics = discoveredTechniques
    .filter(t => t.detectionLayers.includes('heuristics'))
    .map(t => ({ type: 'heuristic', name: t.regressionTest, techniqueId: t.id, principle: t.principle }));

  const suggestedSemanticPatterns = discoveredTechniques
    .filter(t => t.detectionLayers.includes('semantic'))
    .map(t => ({ type: 'semantic', name: t.regressionTest, techniqueId: t.id, principle: t.principle }));

  const gaps = coverageGaps();

  return {
    campaignId,
    timestamp: new Date().toISOString(),
    summary: {
      totalSamples: codes.length,
      totalFindings: allFindings.length,
      uniqueTechniques: discoveredTechniques.length,
      verdictDistribution: results.reduce((acc, r) => {
        acc[r.verdict] = (acc[r.verdict] || 0) + 1;
        return acc;
      }, {}),
    },
    discoveredTechniques,
    principalConfidence: principalConfidence.sort((a, b) => b.evasionRate - a.evasionRate),
    evasionCategories,
    suggestedRules,
    suggestedHeuristics,
    suggestedSemanticPatterns,
    coverageGaps: gaps,
    totalEvaluations: results.length,
  };
}

function printReport(report) {
  const lines = [];
  lines.push(`=== Campaign Report: ${report.campaignId} ===`);
  lines.push(`Samples: ${report.summary.totalSamples}`);
  lines.push(`Findings: ${report.summary.totalFindings}`);
  lines.push(`Unique techniques: ${report.summary.uniqueTechniques}`);
  lines.push(`Verdicts: ${JSON.stringify(report.summary.verdictDistribution)}`);
  lines.push('');

  if (report.discoveredTechniques.length > 0) {
    lines.push('--- Discovered Techniques ---');
    for (const t of report.discoveredTechniques) {
      lines.push(`  ${t.id}: ${t.name} (${t.category}) — evasion ${(t.avgEvasion * 100).toFixed(1)}% — rule: ${t.rule}`);
    }
    lines.push('');
  }

  lines.push('--- Principle Confidence ---');
  for (const pc of report.principalConfidence) {
    lines.push(`  ${pc.principle}: ${(pc.confidence * 100).toFixed(1)}% confidence (${pc.missed}/${pc.totalTechniques} techniques missed)`);
  }
  lines.push('');

  if (report.suggestedRules.length > 0) {
    lines.push('--- Suggested Rules ---');
    for (const r of report.suggestedRules) {
      lines.push(`  [DETERMINISTIC] ${r.name} (via ${r.techniqueId})`);
    }
  }
  if (report.suggestedHeuristics.length > 0) {
    lines.push('--- Suggested Heuristics ---');
    for (const h of report.suggestedHeuristics) {
      lines.push(`  [HEURISTIC] ${h.name} (via ${h.techniqueId})`);
    }
  }
  if (report.suggestedSemanticPatterns.length > 0) {
    lines.push('--- Suggested Semantic Patterns ---');
    for (const s of report.suggestedSemanticPatterns) {
      lines.push(`  [SEMANTIC] ${s.name} (via ${s.techniqueId})`);
    }
  }
  if (report.coverageGaps.length > 0) {
    lines.push('');
    lines.push('--- Coverage Gaps ---');
    for (const g of report.coverageGaps) {
      lines.push(`  ${g.principle}: ${g.coverage} coverage — ${g.gap}`);
    }
  }

  lines.push('');
  lines.push(`Total evaluations: ${report.totalEvaluations}`);
  lines.push('=== End Report ===');
  return lines.join('\n');
}

module.exports = { generateReport, printReport };
