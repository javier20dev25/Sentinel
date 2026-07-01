/**
 * Sentinel: Scanner Worker (v1.0)
 * 
 * Offloads CPU-intensive semantic scanning and risk orchestration
 * to a separate thread to keep the main event loop responsive.
 */

const { parentPort, workerData } = require('worker_threads');
const path = require('path');
const scanner = require(path.join(__dirname, '../../../../packages/sentinel-worker/core/scanner/index'));
const scoringEngine = require(path.join(__dirname, '../../../../packages/sentinel-worker/core/scanner/scoring_engine'));

async function run() {
    const { filename, patch, author, repoName, prNumber, eventId } = workerData;
    
    try {
        // 1. Scan individual file patch (CPU Intensive Regex/Semantic)
        const scanResult = await scanner.scanFile(filename, patch);
        
        // 2. Return raw results back to main thread
        // We do NOT finalize the verdict here to keep the worker "pure"
        // and avoid race conditions in ThreatMemory.
        parentPort.postMessage({
            status: 'success',
            filename,
            patchSize: patch.length,
            scanResult,
            repoName,
            prNumber,
            eventId
        });
    } catch (err) {
        if (err.message?.includes('SCAN_TIMEOUT')) {
            // Logic for handling timeout
        }
        parentPort.postMessage({
            status: 'error',
            error: err.message,
            filename
        });
    }
}

run();
