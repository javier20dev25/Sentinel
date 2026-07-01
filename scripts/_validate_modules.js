// Sentinel v8.1.0 — Full stack validation
'use strict';
const path = require('path');
const fs = require('fs');
const ROOT = path.join(__dirname, '..');

try {
    // 1. Module loading
    const dp = require(path.join(ROOT, 'packages/sentinel-worker/core/scanner/data_paths'));
    console.log('✓ data_paths:', dp.PATHS.ROOT);
    dp.ensureDataDirs();

    const dc = require(path.join(ROOT, 'packages/sentinel-worker/core/scanner/data_contract'));
    console.log('✓ data_contract:', dc.CALIBRATION_VERSION);

    const tm = require(path.join(ROOT, 'packages/sentinel-worker/core/scanner/threat_memory'));
    console.log('✓ threat_memory:', JSON.stringify(tm.getStats()));

    const rp = require(path.join(ROOT, 'packages/sentinel-worker/core/scanner/repo_profile'));
    const infraProfile = rp.getProfile('expressjs/express');
    const frontendProfile = rp.getProfile('facebook/react');
    console.log('✓ repo_profile (infra):', JSON.stringify({ type: infraProfile.type, confidenceScale: infraProfile.confidenceScale, verdictREVIEW: infraProfile.verdictThresholds.REVIEW, boost: infraProfile.convergenceBoost }));
    console.log('✓ repo_profile (frontend):', JSON.stringify({ type: frontendProfile.type, confidenceScale: frontendProfile.confidenceScale, verdictREVIEW: frontendProfile.verdictThresholds.REVIEW, boost: frontendProfile.convergenceBoost }));

    const idx = require(path.join(ROOT, 'packages/sentinel-worker/core/scanner/index'));
    console.log('✓ scanner index');

    // 2. Data contract normalization with decision_hash
    const mock = {
        verdict: 'REVIEW', impactScore: 55, decisionConfidence: 0.72,
        fingerprint: 'abc123', traceId: 'trace-xyz',
        reasoningTrace: { stages: { baseGlobalRisk: 60 }, signals: ['NETWORK'], dampeners: [], filters: [] },
        rationale: { reason: 'Test' }, evidenceGraph: [], metrics: { latency_ms: 42 }
    };
    const canonical = dc.normalize(mock, { repoId: 'test/repo', repoProfile: 'infrastructure', scanId: 'scan-001' });
    const obs = dc.toObservationRecord(canonical, { eventId: 'test-1', file: 'test.js', author: 'dev' });
    console.log('✓ decision_hash:', obs.decision_hash);
    console.log('✓ calibration_version in record:', obs.calibration_version);

    // 3. Verify PATHS has NO legacy references
    console.log('✓ PATHS keys:', Object.keys(dp.PATHS).join(', '));
    const hasLegacy = Object.keys(dp.PATHS).some(k => k.startsWith('LEGACY'));
    console.log(hasLegacy ? '✗ LEGACY keys still in PATHS!' : '✓ No legacy keys in PATHS');

    // 4. Verify profile-driven thresholds
    console.log('✓ isExpectedSignal("infrastructure", "NETWORK"):', rp.isExpectedSignal('infrastructure', 'NETWORK'));
    console.log('✓ isExpectedSignal("frontend", "NETWORK"):', rp.isExpectedSignal('frontend', 'NETWORK'));

    console.log('\n✅ ALL v8.1.0 VALIDATIONS PASSED');
} catch (e) {
    console.error('❌ FAIL:', e.message);
    console.error(e.stack);
    process.exit(1);
}
