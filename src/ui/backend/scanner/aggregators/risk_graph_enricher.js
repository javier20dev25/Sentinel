/**
 * Sentinel: Risk Graph Enrichment Engine (v1.0)
 * 
 * Orchestrates the flow of data between the runtime context and the persistent Risk Graph.
 * Enables playbooks to make decisions based on global entity reputation.
 */

'use strict';

const riskGraph = require('./risk_graph');

class RiskGraphEnricher {
    /**
     * Enriches the runtime context with global intelligence from the Risk Graph.
     * 
     * @param {Object} context - The active SPL execution context.
     * @returns {Object} The enriched context.
     */
    static enrich(context) {
        if (!context) return context;

        // 1. Enrich Package Metadata
        if (context.package && context.package.name) {
            const stats = riskGraph.getPackageStats(context.package.name);
            context.package.global = {
                risk_score: stats.risk_score || 0,
                seen_count: stats.seen_count || 0,
                block_count: stats.block_count || 0,
                is_previously_blocked: stats.block_count > 0,
                last_seen: stats.last_seen
            };
            
            // Detect temporal spikes (burst signals in last 24h)
            const spikes = riskGraph.getTemporalSpikes(`package:${context.package.name}`, 24);
            context.package.global.temporal_spike_24h = spikes.count;
        }

        // 2. Enrich Repository Metadata
        if (context.repo && context.repo.fullName) {
            const repoId = `repository:${context.repo.fullName}`;
            const spikes = riskGraph.getTemporalSpikes(repoId, 24);
            context.repo.global = {
                activity_spike_24h: spikes.count
            };
        }

        return context;
    }

    /**
     * Records the execution outcome and signals in the Risk Graph.
     * 
     * @param {Object} context - Execution context post-decision.
     * @param {Object} verdict - Final decision made by the playbook.
     */
    static record(context, verdict) {
        if (!context) return;

        const repoId = context.repo?.fullName ? `repository:${context.repo.fullName}` : null;
        const pkgId = context.package?.name ? `package:${context.package.name}` : null;

        // Register nodes
        if (repoId) riskGraph.addNode('repository', context.repo.fullName);
        if (pkgId) riskGraph.addNode('package', context.package.name);

        // Record package usage in repository
        if (repoId && pkgId) {
            riskGraph.addEdge(pkgId, repoId, 'used_by');
        }

        // Record signals
        if (context.signals && Array.isArray(context.signals.raw)) {
            context.signals.raw.forEach(signal => {
                const signalId = `signal:${signal.source}:${signal.rule_id || 'unknown'}`;
                riskGraph.addNode('signal', signalId, { weight: signal.weight });
                
                if (pkgId) riskGraph.addEdge(signalId, pkgId, 'affected');
                if (repoId) riskGraph.addEdge(signalId, repoId, 'triggered_in');
            });
        }

        // Record decision
        if (verdict && (pkgId || repoId)) {
            const decisionId = `decision:${Date.now()}`;
            riskGraph.addNode('decision', decisionId, { verdict: verdict.verdict });
            
            if (pkgId) {
                const edgeType = verdict.verdict === 'block' ? 'blocked_in' : 'allowed_in';
                riskGraph.addEdge(`package:${context.package.name}`, decisionId, edgeType);
            }
        }

        // Persist updates
        riskGraph.persist();
    }
}

module.exports = RiskGraphEnricher;
