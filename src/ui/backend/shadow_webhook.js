/**
 * Sentinel: Shadow Mode Telemetry Receiver (v8.1.0 - Observations Complete)
 * 
 * Silent deployment endpoint. Ingests real PR traffic via webhooks.
 * ALL outputs pass through the Canonical Data Contract.
 * 
 * INVARIANT: Every file evaluation writes to observations.jsonl.
 *            No exceptions. PASS or BLOCK, it goes in.
 * 
 * Telemetry Streams:
 *   OBSERVATIONS  — Every decision (denominator for FPR)
 *   DETECTIONS    — High-signal alerts only (numerator for SOC)
 *   METRICS       — Per-PR aggregate latency/verdict
 *   CALIBRATION   — Per-repo-class precision/recall snapshots
 *   STRESS        — Isolated stress-test telemetry (opt-in via _stressTest flag)
 */

'use strict';

const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const GitHubBridge = require('./lib/gh_bridge');
const RepoProfile = require('../../../packages/sentinel-worker/core/scanner/repo_profile');
const ThreatMemory = require('../../../packages/sentinel-worker/core/scanner/threat_memory');
const DataContract = require('../../../packages/sentinel-worker/core/scanner/data_contract');
const { PATHS, ensureDataDirs, migrateLegacyData, retireLegacyFiles } = require('../../../packages/sentinel-worker/core/scanner/data_paths');

const app = express();
app.use(express.json());

// Initialize unified data directory and retire legacy files
ensureDataDirs();
migrateLegacyData();
retireLegacyFiles();

const deliveryCache = new Set();
const MAX_CACHE_SIZE = 1000;

// Buffered writer — batches to disk every 2s to avoid I/O contention
const WRITE_BUFFER = { observations: [], detections: [], metrics: [], calibration: [] };
const FLUSH_INTERVAL_MS = 2000;

function flushBuffers() {
    const pathMap = {
        observations: PATHS.OBSERVATIONS,
        detections:   PATHS.DETECTIONS,
        metrics:      PATHS.METRICS,
        calibration:  PATHS.CALIBRATION
    };
    for (const [key, buffer] of Object.entries(WRITE_BUFFER)) {
        if (buffer.length === 0) continue;
        try {
            const data = buffer.map(r => JSON.stringify(r)).join('\n') + '\n';
            fs.appendFileSync(pathMap[key], data, 'utf8');
        } catch (e) {
            console.error(`[SHADOW] Write error (${key}):`, e.message);
        }
        buffer.length = 0;
    }
}

const flushTimer = setInterval(flushBuffers, FLUSH_INTERVAL_MS);

// --- CALIBRATION ACCUMULATOR (per-repo-class) ---
const calibrationWindow = {};

function accumulateCalibration(repoClass, canonical) {
    if (!calibrationWindow[repoClass]) {
        calibrationWindow[repoClass] = { total: 0, flagged: 0, passCount: 0, impactSum: 0, confSum: 0 };
    }
    const w = calibrationWindow[repoClass];
    w.total++;
    w.impactSum += canonical.effectiveImpact;
    w.confSum += canonical.decisionConfidence;
    if (canonical.verdict === 'PASS') w.passCount++;
    else w.flagged++;

    // Emit calibration snapshot every 50 observations per class
    if (w.total % 50 === 0) {
        const snapshot = {
            timestamp: new Date().toISOString(),
            repo_class: repoClass,
            calibration_version: DataContract.CALIBRATION_VERSION,
            window_size: w.total,
            pass_rate: Math.round((w.passCount / w.total) * 10000) / 100,
            flag_rate: Math.round((w.flagged / w.total) * 10000) / 100,
            avg_impact: Math.round((w.impactSum / w.total) * 100) / 100,
            avg_confidence: Math.round((w.confSum / w.total) * 1000) / 1000
        };
        WRITE_BUFFER.calibration.push(snapshot);
        console.log(`[CALIBRATION] ${repoClass}: ${snapshot.pass_rate}% pass | ${snapshot.flag_rate}% flagged | avg_impact=${snapshot.avg_impact}`);
    }
}

app.post('/webhook/github', async (req, res) => {
    const deliveryId = req.headers['x-github-delivery'] || `manual-${Date.now()}`;
    
    if (deliveryCache.has(deliveryId)) {
        return res.status(200).send({ status: 'Duplicate delivery skipped' });
    }
    deliveryCache.add(deliveryId);
    if (deliveryCache.size > MAX_CACHE_SIZE) {
        const first = deliveryCache.values().next().value;
        deliveryCache.delete(first);
    }

    res.status(202).send({ status: 'Shadow scan queued' });

    try {
        const payload = req.body;
        // FIXED: _mockFiles is NOT a stress test. It's a mock data source.
        // Only explicit _stressTest flag routes to the isolated stress stream.
        const isStressTest = !!payload._stressTest;
        
        if (!payload.pull_request && !payload._mockFiles) return;
        
        const repoName = payload.repository?.full_name || payload.pull_request?.base?.repo?.full_name || 'unknown-repo';
        const prNumber = payload.pull_request?.number || 0;
        const author = payload.sender ? payload.sender.login : 'unknown';
        const eventId = `shadow-${deliveryId}`;
        const repoProfile = RepoProfile.getProfile(repoName);

        const workerPool = require('./lib/worker_pool');
        const scanner = require('../../../packages/sentinel-worker/core/scanner/index');
        const startTime = Date.now();

        let files = payload._mockFiles || await GitHubBridge.fetchPRFiles(repoName, prNumber);
        
        const scanPromises = files
            .filter(file => file.patch && GitHubBridge.isRiskyFile(file.filename))
            .map(file => workerPool.runTask({
                filename: file.filename,
                patch: file.patch,
                author,
                repoName,
                prNumber,
                eventId
            }));

        const workerResults = await Promise.allSettled(scanPromises);
        let highestImpact = 0;
        let overallVerdict = 'PASS';
        let scannedCount = 0;
        const prObservations = [];

        for (const promiseRes of workerResults) {
            if (promiseRes.status === 'rejected') continue;
            scannedCount++;

            const workerRes = promiseRes.value;
            const finalResult = scanner.finalizeVerdict(workerRes.scanResult, [], repoProfile.type, { 
                repoId: repoName, 
                user: author 
            });

            // --- CANONICAL CONTRACT ENFORCEMENT ---
            const canonical = DataContract.normalize(finalResult, {
                scanId: finalResult.scan_id,
                repoId: repoName,
                repoProfile: repoProfile.type,
                file: workerRes.filename,
                author
            });

            if (canonical.effectiveImpact > highestImpact) {
                highestImpact = canonical.effectiveImpact;
                overallVerdict = canonical.verdict;
            }

            // --- DECISION AUDIT HASH (reproducibility proof) ---
            const auditInput = `${canonical.scanId}|${canonical.repoId}|${workerRes.filename}|${canonical.effectiveImpact}|${canonical.verdict}|${canonical.calibrationVersion}`;
            const decisionHash = crypto.createHash('sha256').update(auditInput).digest('hex').substring(0, 12);

            // 1. OBSERVATION — EVERY decision, including PASS. This is the denominator.
            const obsRecord = DataContract.toObservationRecord(canonical, {
                eventId,
                pr: prNumber,
                file: workerRes.filename,
                author,
                includeTrace: false
            });
            obsRecord.decision_hash = decisionHash;

            // ALWAYS write to observations. Stress test flag controls ADDITIONAL copy.
            WRITE_BUFFER.observations.push(obsRecord);
            prObservations.push(obsRecord);

            if (isStressTest) {
                fs.appendFileSync(PATHS.STRESS, JSON.stringify(obsRecord) + '\n', 'utf8');
            }

            // 2. DETECTION — only actionable signals (with full trace)
            if (canonical.effectiveImpact >= 40 || canonical.verdict !== 'PASS') {
                const detRecord = DataContract.toObservationRecord(canonical, {
                    eventId,
                    pr: prNumber,
                    file: workerRes.filename,
                    author,
                    includeTrace: true
                });
                detRecord.decision_hash = decisionHash;
                WRITE_BUFFER.detections.push(detRecord);
                console.log(`[SHADOW] 🚨 DETECTION: ${workerRes.filename} | Impact: ${canonical.effectiveImpact} | Verdict: ${canonical.verdict} | Hash: ${decisionHash}`);
            }

            // 3. CALIBRATION — per-repo-class accumulation
            accumulateCalibration(repoProfile.type, canonical);
        }

        // 4. Handle PRs where NO files passed the risky-file filter (still an observation)
        if (scannedCount === 0 && files.length > 0) {
            const nullObs = {
                timestamp: new Date().toISOString(),
                event_id: eventId,
                repo: repoName,
                pr: prNumber,
                file: null,
                author,
                raw_impact: 0,
                effective_impact: 0,
                confidence: 0,
                verdict: 'PASS',
                fingerprint: null,
                calibration_version: DataContract.CALIBRATION_VERSION,
                repo_profile: repoProfile.type,
                decision_hash: 'no-risky-files',
                latency_ms: Date.now() - startTime
            };
            WRITE_BUFFER.observations.push(nullObs);
            accumulateCalibration(repoProfile.type, { effectiveImpact: 0, decisionConfidence: 0, verdict: 'PASS' });
        }
        
        // 5. AGGREGATE METRICS — per-PR summary
        const metricsRecord = {
            timestamp: new Date().toISOString(),
            repo: repoName,
            repo_profile: repoProfile.type,
            pr: prNumber,
            files_total: files.length,
            files_scanned: scannedCount,
            peak_impact: highestImpact,
            final_verdict: overallVerdict,
            calibration_version: DataContract.CALIBRATION_VERSION,
            latency_ms: Date.now() - startTime
        };
        WRITE_BUFFER.metrics.push(metricsRecord);

        console.log(`[SHADOW] PR #${prNumber} complete. Scanned: ${scannedCount}/${files.length} | Peak: ${highestImpact} | Verdict: ${overallVerdict}`);

    } catch (err) {
        console.error(`[SHADOW] Pipeline error:`, err.stack);
    }
});

// Flush on shutdown (handles both POSIX and Windows)
function gracefulShutdown() {
    clearInterval(flushTimer);
    flushBuffers();
    process.exit(0);
}
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
process.on('exit', flushBuffers); // last-resort flush

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🛡️ Sentinel Shadow Mode v8.1.0 active on port ${PORT}`);
    console.log(`📂 Data: ${PATHS.ROOT}`);
    console.log(`📊 Streams: observations | detections | metrics | calibration`);
});
