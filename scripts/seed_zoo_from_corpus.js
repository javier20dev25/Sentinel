/**
 * Seed PR Zoo from test corpus.
 *
 * Converts the 84 clean + adversarial test samples into PR Zoo entries
 * with known ground truth (expected verdict, findings, capabilities).
 *
 * These entries have source 'clean_corpus' or 'mutation_lab' and serve
 * as the ground truth anchor for all benchmark metrics.
 *
 * Usage: node scripts/seed_zoo_from_corpus.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cleanSamples = require('../packages/sentinel-core/scanner/evasion/__tests__/clean_corpus');
const evasionSamples = require('../packages/sentinel-core/scanner/evasion/__tests__/adversarial_corpus');
const knowledgeBase = require('../packages/sentinel-core/scanner/evasion/knowledge_base.json');
const { produce: baselineProduce } = require('../packages/sentinel-core/adapters/baseline_adapter');

const ZOO_DIR = path.join(__dirname, '..', 'data', 'pr_zoo');
const PATCHES_DIR = path.join(ZOO_DIR, 'patches');
const MANIFEST_PATH = path.join(ZOO_DIR, 'manifest.json');

if (!fs.existsSync(PATCHES_DIR)) fs.mkdirSync(PATCHES_DIR, { recursive: true });

// ── Ground Truth Definitions ──
// Derived from evasion.test.js assertions

const ADVERSARIAL_GT = {
  bracketNotationExec: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-001', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  bracketNotationSpawn: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'IR-001', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  stringConcatRequire: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-002', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport', 'Execution'],
  },
  stringConcatChained: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['ModuleImport', 'Execution'],
  },
  hexEscapedRequire: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-003', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport', 'Execution'],
  },
  unicodeEscapedRequire: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-004', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport', 'Execution'],
  },
  evalDirect: {
    verdict: 'CRITICAL',
    findings: [{ techniqueId: 'EVASION-013', severity: 'CRITICAL' }],
    capabilities: ['DynamicCodeExecution'],
  },
  evalDecode: {
    verdict: 'CRITICAL',
    findings: [{ techniqueId: 'SIG-003', severity: 'CRITICAL' }],
    capabilities: ['DynamicCodeExecution', 'Decode'],
  },
  functionConstructor: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-014', severity: 'HIGH' }],
    capabilities: ['DynamicCodeExecution'],
  },
  constructorChain: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-007', severity: 'HIGH' }],
    capabilities: ['ReflectionAccess'],
  },
  globalThisReflect: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-017', severity: 'MEDIUM' }],
    capabilities: ['ReflectionAccess', 'GlobalAccess'],
  },
  shellPivot: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-012', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  vmEscape: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-015', severity: 'CRITICAL' }],
    capabilities: ['SandboxEscape'],
  },
  moduleConstructor: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-016', severity: 'HIGH' }],
    capabilities: ['ModuleImport'],
  },
  workerThreads: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-035', severity: 'MEDIUM' }],
    capabilities: ['Execution'],
  },
  dynamicRequire: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-028', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport'],
  },
  prototypePollution: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-027', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  promptInjectIgnore: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-008', severity: 'MEDIUM' }],
    capabilities: [],
  },
  promptInjectSystemMarker: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-009', severity: 'MEDIUM' }],
    capabilities: [],
  },
  promptToolMisuse: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-010', severity: 'MEDIUM' }],
    capabilities: [],
  },
  agentAutonomyEvasion: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: [],
  },
  codeSynthesis: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'SEM-009', severity: 'HIGH' }],
    capabilities: ['DynamicCodeExecution'],
  },
  jsonRpcInjection: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-018', severity: 'HIGH' }],
    capabilities: ['NetworkAccess'],
  },
  multiLayerDecode: {
    verdict: 'CRITICAL',
    findings: [{ techniqueId: 'EVASION-020', severity: 'CRITICAL' }],
    capabilities: ['Decode', 'DynamicCodeExecution'],
  },
  outboundFetch: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-021', severity: 'MEDIUM' }],
    capabilities: ['NetworkAccess'],
  },
  outboundWebSocket: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['NetworkAccess'],
  },
  obfuscatedIdentifiers: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: [],
  },
  hardcodedSecret: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: [],
  },
  maliciousLifecycle: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['Execution'],
  },
  suspiciousRegistry: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['ModuleImport'],
  },
  obfuscatorIoPattern: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: [],
  },
  delayedExecString: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['DelayedExecution'],
  },
  setImmediateString: {
    verdict: 'SUSPICIOUS',
    findings: [],
    capabilities: ['DelayedExecution'],
  },
  arrayPropertyObfuscation: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'IR-002', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },

  // ── Missing GT entries (were falling back to CLEAN) ──

  functionStringArg: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-014b', severity: 'MEDIUM' }],
    capabilities: ['DynamicCodeExecution'],
  },
  shellPivotWget: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-012', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  prototypePollution2: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-027', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  innerHTMLXSS: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-034', severity: 'MEDIUM' }],
    capabilities: ['BrowserAccess'],
  },
  homoglyph: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-019', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport'],
  },
  highEntropy: {
    verdict: 'CLEAN',
    findings: [],
    capabilities: [],
  },
  childProcessAlias: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'SEM-001', severity: 'MEDIUM' }, { techniqueId: 'IR-002', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  conditionalEvasion: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'SEM-001', severity: 'MEDIUM' }, { techniqueId: 'IR-002', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
  typosquat: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'SIG-005', severity: 'MEDIUM' }],
    capabilities: ['ModuleImport'],
  },
  encodedLifecycle: {
    verdict: 'CRITICAL',
    findings: [
      { techniqueId: 'EVASION-013', severity: 'CRITICAL' },
      { techniqueId: 'EVASION-025', severity: 'HIGH' },
      { techniqueId: 'EVASION-030', severity: 'HIGH' },
      { techniqueId: 'SIG-003', severity: 'MEDIUM' },
      { techniqueId: 'SIG-007', severity: 'MEDIUM' },
    ],
    capabilities: ['DynamicCodeExecution', 'Decode'],
  },
  envSecretRef: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-024', severity: 'LOW' }],
    capabilities: ['SecretAccess'],
  },
  longEncodedBlob: {
    verdict: 'CLEAN',
    findings: [],
    capabilities: [],
  },
  promptToolJsonRpc: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-010b', severity: 'MEDIUM' }],
    capabilities: ['PromptInjection'],
  },
  promptLeak: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'SEM-008', severity: 'MEDIUM' }],
    capabilities: ['InformationDisclosure'],
  },
};

// Known exceptions in clean corpus
const CLEAN_EXCEPTIONS = {
  unitTestEval: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-013', severity: 'CRITICAL' }],
    capabilities: ['DynamicCodeExecution'],
  },
  npmScript: {
    verdict: 'SUSPICIOUS',
    findings: [{ techniqueId: 'EVASION-025', severity: 'HIGH' }],
    capabilities: ['Execution'],
  },
};

// ── Helpers ──

function makeExpected(verdict, findings, capabilities, source) {
  return {
    verdict,
    riskScore: verdict === 'CRITICAL' ? 0.9 : verdict === 'SUSPICIOUS' ? 0.6 : 0,
    findings: findings.map(f => ({
      type: f.techniqueId || 'generic',
      techniqueId: f.techniqueId || null,
      severity: f.severity || 'MEDIUM',
    })),
    capabilities,
    source,
    labelDate: new Date().toISOString(),
  };
}

function safeId(prefix, name) {
  return `${prefix}_${name}`;
}

function seedSamples(samples, prefix, gtMap, exceptions) {
  const entries = [];
  for (const [name, code] of Object.entries(samples)) {
    const id = safeId(prefix, name);
    const patchHash = crypto.createHash('sha256').update(code).digest('hex');
    const patchFile = path.join(PATCHES_DIR, `${id}.patch`);
    const metaFile = path.join(PATCHES_DIR, `${id}.json`);

    // Skip if already exists
    if (fs.existsSync(patchFile)) {
      console.log(`  SKIP ${id} — already in zoo`);
      entries.push(id);
      continue;
    }

    // Determine ground truth
    const gt = gtMap[name] || (exceptions && exceptions[name]);
    const expected = gt
      ? makeExpected(gt.verdict, gt.findings, gt.capabilities, prefix === 'adversarial' ? 'mutation_lab' : 'clean_corpus')
      : makeExpected('CLEAN', [], [], 'clean_corpus');

    // Source metadata
    const source = {
      id,
      repo: prefix === 'adversarial' ? 'sentinel/adversarial' : 'sentinel/clean',
      pr: 0,
      url: '',
      profile: 'benchmark',
      description: name,
      state: 'closed',
      sha: '',
      user: 'sentinel-benchmark',
      files_changed: 1,
      patchSize: code.length,
      patchHash,
    };

    // Baseline analysis
    let baselineResult = null;
    try {
      baselineResult = baselineProduce(source, { isAudit: true });
    } catch (e) {
      baselineResult = { verdict: 'ERROR', riskScore: 0, statistics: { totalFindings: 0 }, capabilities: [] };
    }

    // Save patch
    fs.writeFileSync(patchFile, code, 'utf8');

    // Save metadata
    const meta = {
      source,
      expected,
      baseline: {
        verdict: baselineResult.verdict,
        riskScore: baselineResult.riskScore,
        findings: baselineResult.statistics?.totalFindings || 0,
        capabilities: baselineResult.capabilities || [],
      },
      collected_at: new Date().toISOString(),
    };
    fs.writeFileSync(metaFile, JSON.stringify(meta, null, 2), 'utf8');

    console.log(`  ✓ ${id} — expected=${expected.verdict} baseline=${baselineResult.verdict}`);
    entries.push(id);
  }
  return entries;
}

// ── Main ──
function start() {
  console.log('═'.repeat(50));
  console.log('SEED ZOO FROM CORPUS');
  console.log('═'.repeat(50));

  console.log('\nSeeding clean corpus...');
  const cleanIds = seedSamples(cleanSamples, 'clean', {}, CLEAN_EXCEPTIONS);

  console.log('\nSeeding adversarial corpus...');
  const advIds = seedSamples(evasionSamples, 'adversarial', ADVERSARIAL_GT, {});

  // Build manifest
  const allEntries = [];
  for (const id of [...cleanIds, ...advIds]) {
    const metaFile = path.join(PATCHES_DIR, `${id}.json`);
    if (!fs.existsSync(metaFile)) continue;
    try {
      const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      const patchFile = path.join(PATCHES_DIR, `${id}.patch`);
      const patchSize = fs.existsSync(patchFile) ? fs.statSync(patchFile).size : 0;

      allEntries.push({
        id,
        repo: meta.source.repo || 'unknown',
        pr: meta.source.pr || 0,
        profile: meta.source.profile || 'unknown',
        title: meta.source.description || '',
        user: meta.source.user || '',
        files_changed: meta.source.files_changed || 0,
        patchSize,
        patchHash: meta.source.patchHash || '',
        baselineVerdict: meta.baseline?.verdict || 'CLEAN',
        baselineRiskScore: meta.baseline?.riskScore || 0,
        expectedVerdict: meta.expected?.verdict || null,
        expectedSource: meta.expected?.source || null,
        collected_at: meta.collected_at || '',
      });
    } catch (e) {}
  }

  // Load existing manifest entries (PR Zoo real PRs) and merge
  let existingEntries = [];
  if (fs.existsSync(MANIFEST_PATH)) {
    try {
      const existing = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
      existingEntries = (existing.entries || []).filter(
        e => !e.id.startsWith('clean_') && !e.id.startsWith('adversarial_')
      );
      console.log(`\nMerging with ${existingEntries.length} existing PR Zoo entries`);
    } catch (e) {}
  }

  const mergedEntries = [...existingEntries, ...allEntries];
  const manifest = {
    version: 2,
    generated: new Date().toISOString(),
    entries: mergedEntries,
    stats: {
      totalEntries: mergedEntries.length,
      withExpected: mergedEntries.filter(e => e.expectedVerdict).length,
      totalPatchBytes: mergedEntries.reduce((s, e) => s + e.patchSize, 0),
      uniqueRepos: new Set(mergedEntries.map(e => e.repo)).size,
      corpusEntries: allEntries.length,
      prEntries: existingEntries.length,
    },
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2), 'utf8');

  console.log('\n' + '═'.repeat(50));
  console.log('SEED COMPLETE');
  console.log(`  New corpus entries: ${allEntries.length}`);
  console.log(`  Total zoo entries: ${mergedEntries.length}`);
  console.log(`  With ground truth: ${manifest.stats.withExpected}`);
  console.log(`  Manifest: ${MANIFEST_PATH}`);
  console.log('═'.repeat(50));
}

start();
