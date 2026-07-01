/**
 * Sentinel: Temporal Threat Memory (v3.0 - Production Hardened)
 * 
 * Implements an append-only JSONL event stream for repository risk trends.
 * 
 * Architecture:
 *   A. Event Stream (append-only) — source of truth
 *   B. Snapshots — periodic compaction for fast startup
 *   C. Replay — rebuild state from snapshot + events
 * 
 * Designed for determinism, crash-safety, and auditability.
 * Never overwrites existing state. Never mixes log types.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { PATHS, ensureDataDirs } = require('./data_paths');

const SNAPSHOT_INTERVAL = 500; // Create snapshot every N events

class ThreatMemory {
    constructor() {
        this.dbPath = PATHS.MEMORY_EVENTS;
        this.snapshotDir = PATHS.MEMORY_SNAPSHOTS;
        this.state = {};
        this.eventCount = 0;
        this.eventsSinceSnapshot = 0;
        ensureDataDirs();
        this._bootstrap();
    }

    /**
     * Replays the event stream to rebuild the current state.
     * Loads latest snapshot first, then replays events after it.
     */
    _bootstrap() {
        // Try loading from snapshot first
        const snapshot = this._loadLatestSnapshot();
        if (snapshot) {
            this.state = snapshot.state;
            this.eventCount = snapshot.eventCount;
            console.log(`[ThreatMemory] Restored from snapshot (${this.eventCount} events, ${Object.keys(this.state).length} repos)`);
        }

        // Replay events after snapshot
        if (!fs.existsSync(this.dbPath)) {
            if (!snapshot) this.state = {};
            return;
        }

        const lines = fs.readFileSync(this.dbPath, 'utf8').split('\n');
        let replayed = 0;
        let skipped = 0;

        for (const line of lines) {
            if (!line.trim()) continue;
            try {
                const cleanLine = line.replace(/^\uFEFF/, '').trim();
                const event = JSON.parse(cleanLine);
                
                // Skip events already covered by snapshot
                if (snapshot && (event.seq ? event.seq <= snapshot.eventCount : replayed < snapshot.eventCount)) {
                    if (!event.seq) replayed++;
                    continue;
                }
                
                this._applyEvent(event);
                replayed++;
                this.eventCount++;
            } catch (e) {
                skipped++;
            }
        }

        this.eventsSinceSnapshot = replayed;

        if (skipped > 0) {
            console.error(`[ThreatMemory] Skipped ${skipped} corrupted lines during replay`);
        }
        console.log(`[ThreatMemory] Ready: ${Object.keys(this.state).length} repos, ${this.eventCount} events total`);
    }

    _applyEvent(event) {
        const { repoId, type, data } = event;
        if (!this.state[repoId]) {
            this.state[repoId] = {
                rollingRisk: 0,
                trustTrend: 1.0,
                convergenceScore: 0,
                rollingConfidence: 0,
                scanCount: 0,
                trajectory: [],
                benignPatternFrequency: 0,
                labels: {}, // fingerprint -> type (FALSE_POSITIVE, TRUE_POSITIVE)
                lastSeen: 0
            };
        }

        const current = this.state[repoId];

        switch (type) {
            case 'SCAN_UPDATE':
                current.rollingRisk = 0.75 * current.rollingRisk + 0.25 * (data.score / 100);
                current.rollingConfidence = Math.max(current.rollingConfidence, data.confidence || 0);
                current.trajectory.push({ vector: data.vector, risk: data.score, timestamp: event.timestamp });
                if (current.trajectory.length > 10) current.trajectory.shift();
                
                current.convergenceScore = this._calcAcceleration(current.trajectory);
                
                if (data.verdict === 'PASS') {
                    current.trustTrend = Math.min(1.0, current.trustTrend + 0.02);
                    current.benignPatternFrequency++;
                } else {
                    current.trustTrend = Math.max(0.0, current.trustTrend - 0.20);
                }
                
                current.scanCount++;
                current.lastSeen = event.timestamp;
                break;
            
            case 'LABEL_UPDATE':
                current.labels[data.fingerprint] = data.labelType;
                if (data.labelType === 'FALSE_POSITIVE') {
                    current.trustTrend = Math.min(1.0, current.trustTrend + 0.15);
                } else if (data.labelType === 'TRUE_POSITIVE') {
                    current.trustTrend = Math.max(0.0, current.trustTrend - 0.30);
                }
                break;
            
            case 'RESET':
                this.state[repoId] = undefined;
                break;
        }
    }

    getRepoHistory(repoId) {
        return this.state[repoId] || { 
            rollingRisk: 0, 
            trustTrend: 1.0, 
            convergenceScore: 0,
            rollingConfidence: 0,
            scanCount: 0,
            trajectory: [],
            benignPatternFrequency: 0,
            labels: {}
        };
    }

    /**
     * Persists a new scan event to the append-only log.
     */
    update(repoId, stats) {
        const intents = stats.metrics.unique_intents || [];
        const vector = [
            intents.includes('NETWORK') ? 1 : 0,
            intents.includes('EXECUTION') ? 1 : 0,
            intents.includes('SECRET_ACCESS') ? 1 : 0,
            intents.includes('OBFUSCATION_CHAIN') ? 1 : 0,
            intents.includes('SYSTEM_TAMPERING') ? 1 : 0
        ];

        const event = {
            seq: this.eventCount + 1,
            timestamp: Date.now(),
            repoId,
            type: 'SCAN_UPDATE',
            data: {
                score: stats.score,
                confidence: stats.confidence,
                verdict: stats.verdict,
                vector
            }
        };

        this._persist(event);
        this._applyEvent(event);
        this.eventCount++;
        this.eventsSinceSnapshot++;

        // Auto-snapshot after N events
        if (this.eventsSinceSnapshot >= SNAPSHOT_INTERVAL) {
            this._createSnapshot();
        }
    }

    /**
     * Records a human-provided label for an alert fingerprint.
     * @param {string} repoId 
     * @param {string} fingerprint 
     * @param {string} labelType - 'FALSE_POSITIVE' | 'TRUE_POSITIVE'
     */
    addLabel(repoId, fingerprint, labelType) {
        const event = {
            seq: this.eventCount + 1,
            timestamp: Date.now(),
            repoId,
            type: 'LABEL_UPDATE',
            data: { fingerprint, labelType }
        };
        this._persist(event);
        this._applyEvent(event);
        this.eventCount++;
        this.eventsSinceSnapshot++;
    }

    _persist(event) {
        try {
            const dir = path.dirname(this.dbPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            
            // Write with explicit UTF-8 and newline, no BOM
            fs.appendFileSync(this.dbPath, JSON.stringify(event) + '\n', 'utf8');
        } catch (e) {
            console.error("[ThreatMemory] Write failed:", e.message);
        }
    }

    // --- SNAPSHOT SYSTEM ---

    _createSnapshot() {
        try {
            if (!fs.existsSync(this.snapshotDir)) {
                fs.mkdirSync(this.snapshotDir, { recursive: true });
            }

            const snapshot = {
                version: 'v3.0',
                createdAt: new Date().toISOString(),
                eventCount: this.eventCount,
                repoCount: Object.keys(this.state).length,
                state: JSON.parse(JSON.stringify(this.state)) // deep clone
            };

            const filename = `snapshot_${Date.now()}.json`;
            fs.writeFileSync(
                path.join(this.snapshotDir, filename),
                JSON.stringify(snapshot, null, 2),
                'utf8'
            );

            this.eventsSinceSnapshot = 0;
            console.log(`[ThreatMemory] Snapshot created: ${filename} (${this.eventCount} events)`);

            // Compaction: truncate events.jsonl to prevent storage bloat
            try {
                fs.writeFileSync(this.dbPath, '', 'utf8');
                console.log(`[ThreatMemory] Compacted events.jsonl (storage bloat prevented)`);
            } catch (e) {
                console.error("[ThreatMemory] Failed to compact events.jsonl:", e.message);
            }

            // Retain only the 3 most recent snapshots
            this._pruneSnapshots(3);
        } catch (e) {
            console.error("[ThreatMemory] Snapshot creation failed:", e.message);
        }
    }

    _loadLatestSnapshot() {
        try {
            if (!fs.existsSync(this.snapshotDir)) return null;
            
            const files = fs.readdirSync(this.snapshotDir)
                .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
                .sort()
                .reverse();
            
            if (files.length === 0) return null;

            const latest = JSON.parse(fs.readFileSync(path.join(this.snapshotDir, files[0]), 'utf8'));
            return latest;
        } catch (e) {
            console.error("[ThreatMemory] Snapshot load failed:", e.message);
            return null;
        }
    }

    _pruneSnapshots(keepCount) {
        try {
            const files = fs.readdirSync(this.snapshotDir)
                .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
                .sort()
                .reverse();
            
            for (let i = keepCount; i < files.length; i++) {
                fs.unlinkSync(path.join(this.snapshotDir, files[i]));
            }
        } catch (e) {
            // Non-fatal: old snapshots linger but don't corrupt
        }
    }

    // --- ANALYTICAL ---

    _calcAcceleration(trajectory) {
        if (trajectory.length < 3) return 0;
        
        const t0 = trajectory[trajectory.length - 3].risk || 0;
        const t1 = trajectory[trajectory.length - 2].risk || 0;
        const t2 = trajectory[trajectory.length - 1].risk || 0;
        
        const v1 = t1 - t0;
        const v2 = t2 - t1;
        const acc = v2 - v1;
        
        const latestEntry = trajectory[trajectory.length - 1];
        const uniqueSum = latestEntry.vector ? latestEntry.vector.reduce((a, b) => a + b, 0) : 0;
        
        let base = uniqueSum / 5;
        if (acc > 10) base += 0.4;
        
        return Math.min(1.0, base);
    }

    /**
     * Generates a deterministic fingerprint for a finding set.
     */
    generateFingerprint(signals) {
        const sigs = (signals || []).map(s => `${s.intent}:${s.severity}`).sort().join('|');
        return crypto.createHash('sha256').update(sigs).digest('hex').substring(0, 16);
    }

    /**
     * Returns diagnostic stats for health checks.
     */
    getStats() {
        return {
            repoCount: Object.keys(this.state).length,
            totalEvents: this.eventCount,
            eventsSinceSnapshot: this.eventsSinceSnapshot,
            repos: Object.entries(this.state).map(([id, s]) => ({
                repoId: id,
                scanCount: s?.scanCount || 0,
                trustTrend: s?.trustTrend || 1.0,
                labelCount: Object.keys(s?.labels || {}).length
            }))
        };
    }
}

module.exports = new ThreatMemory();
