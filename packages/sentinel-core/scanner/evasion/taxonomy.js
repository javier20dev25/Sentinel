'use strict';

const knowledgeBase = require('./knowledge_base.json');

const PRINCIPLE_INDEX = new Map();
for (const taxon of knowledgeBase.taxonomy) {
  PRINCIPLE_INDEX.set(taxon.id, taxon);
}

const TECHNIQUE_INDEX = new Map();
for (const tech of knowledgeBase.techniques) {
  TECHNIQUE_INDEX.set(tech.id, tech);
}

function classifyFindings(findings) {
  const classified = [];
  for (const f of findings) {
    const techId = f.id;
    const tech = TECHNIQUE_INDEX.get(techId);
    const taxonId = tech ? tech.taxonomyId : null;
    const principle = taxonId ? PRINCIPLE_INDEX.get(taxonId) : null;
    classified.push({
      finding: f,
      technique: tech || null,
      principle: principle || null,
    });
  }
  return classified;
}

function groupByPrinciple(classified) {
  const groups = {};
  for (const item of classified) {
    const pId = item.principle ? item.principle.id : 'UNCLASSIFIED';
    if (!groups[pId]) {
      groups[pId] = {
        principle: item.principle,
        findings: [],
        techniques: new Set(),
      };
    }
    groups[pId].findings.push(item.finding);
    if (item.technique) {
      groups[pId].techniques.add(item.technique.name);
    }
  }
  for (const g of Object.values(groups)) {
    g.techniques = [...g.techniques];
  }
  return groups;
}

function coverageGaps() {
  const gaps = [];
  for (const taxon of knowledgeBase.taxonomy) {
    if (taxon.coverage !== 'strong') {
      gaps.push({
        principle: taxon.principle,
        coverage: taxon.coverage,
        gap: taxon.gap,
        techniqueCount: taxon.techniqueIds.length,
        avgEvasion: taxon.avgEvasion,
      });
    }
  }
  return gaps.sort((a, b) => b.avgEvasion - a.avgEvasion);
}

function summarizeCoverage() {
  const summary = { strong: 0, partial: 0, moderate: 0, basic: 0, specific: 0 };
  for (const taxon of knowledgeBase.taxonomy) {
    summary[taxon.coverage]++;
  }
  return summary;
}

module.exports = {
  classifyFindings,
  groupByPrinciple,
  coverageGaps,
  summarizeCoverage,
  PRINCIPLE_INDEX,
  TECHNIQUE_INDEX,
  knowledgeBase,
};
