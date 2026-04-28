/**
 * Sentinel: Intelligence Sync Manager (v1.0)
 * 
 * Orchestrates the synchronization of reputational metadata between
 * the local Risk Graph and the Sentinel Global Intelligence Network.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const riskGraph = require('./risk_graph');
const trustModel = require('./trust_model');

class SyncManager {
    constructor() {
        this.cloudCachePath = path.join(os.homedir(), '.sentinel', 'global_cache.json');
        this.lastSync = null;
    }

    /**
     * Pushes local reputational metadata to the Global Network.
     * Sanitizes data to remove sensitive repository paths before export.
     */
    async push() {
        const localNodes = riskGraph.nodes.package;
        const exportData = {};

        for (const [name, data] of Object.entries(localNodes)) {
            // Only export packages with significant signals or blocks
            const stats = riskGraph.getPackageStats(name);
            if (stats.block_count > 0 || stats.risk_score > 0.5) {
                exportData[name] = {
                    risk_score: stats.risk_score,
                    block_count: stats.block_count,
                    signals: this._summarizeSignals(name),
                    timestamp: new Date().toISOString()
                };
            }
        }

        // Simulate network request
        console.log(`[SYNC] Pushing metadata for ${Object.keys(exportData).length} entities to Sentinel Cloud...`);
        return { success: true, count: Object.keys(exportData).length };
    }

    /**
     * Pulls global reputational metadata and merges it into the local graph.
     */
    async pull() {
        console.log(`[SYNC] Pulling global intelligence manifest...`);
        
        // Mocked global data for Phase 4 demonstration
        const globalManifest = {
            "axois": { risk_score: 0.95, block_count: 150, signals: ["typosquatting"], source: "sentinel-official:main" },
            "malicious-npm-pkg": { risk_score: 1.0, block_count: 500, signals: ["malware"], source: "sentinel-official:main" },
            "suspicious-pkg": { risk_score: 0.7, block_count: 12, signals: ["sandbox_failure"], source: "community:generic" }
        };

        let mergedCount = 0;
        for (const [name, data] of Object.entries(globalManifest)) {
            const weightedScore = trustModel.calculateWeightedScore(data.risk_score, data.source);
            
            // Update the global namespace in the risk graph
            riskGraph.addNode('package', name, {
                global_risk_score: weightedScore,
                global_block_count: data.block_count,
                global_signals: data.signals,
                last_sync: new Date().toISOString()
            });
            mergedCount++;
        }

        riskGraph.persist();
        this.lastSync = new Date().toISOString();
        return { success: true, count: mergedCount };
    }

    _summarizeSignals(packageName) {
        const edges = riskGraph.getRelatedEdges(`package:${packageName}`);
        const signals = edges.filter(e => e.from.startsWith('signal:'))
                             .map(e => e.from.split(':')[1]);
        return [...new Set(signals)];
    }
}

module.exports = new SyncManager();
