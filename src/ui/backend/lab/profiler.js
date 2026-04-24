/**
 * Sentinel Adversarial Lab (SAL): Metrics Profiler (v1.0)
 * 
 * Measures execution latency and resource utilization (CPU/Memory) 
 * during security analysis cycles.
 */

'use strict';

class MetricsProfiler {
    constructor() {
        this.startMark = null;
        this.startMemory = null;
    }

    start() {
        this.startMark = process.hrtime();
        this.startMemory = process.memoryUsage().heapUsed;
    }

    stop() {
        if (!this.startMark) return null;

        const endMark = process.hrtime(this.startMark);
        const endMemory = process.memoryUsage().heapUsed;

        // Convert to milliseconds and bytes
        const latencyMs = (endMark[0] * 1000) + (endMark[1] / 1000000);
        const memoryDelta = endMemory - this.startMemory;

        return {
            latency_ms: parseFloat(latencyMs.toFixed(3)),
            memory_delta_bytes: memoryDelta,
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = new MetricsProfiler();
