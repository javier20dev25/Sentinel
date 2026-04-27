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
            const node = riskGraph.nodes.package[context.package.name] || {};
            
            // ─── Federated Risk Calculation (v1.0) ───
            const localScore = stats.risk_score || 0;
            const globalScore = node.global_risk_score || 0;
            const spikes = riskGraph.getTemporalSpikes(`package:${context.package.name}`, 24);
            const spikeScore = Math.min(spikes.count / 10, 1.0); // Normalized spike score

            const totalRisk = (localScore * 0.5) + (globalScore * 0.3) + (spikeScore * 0.2);

            context.package.global = {
                risk_score: totalRisk,
                local_contribution: localScore,
                network_contribution: globalScore,
                temporal_contribution: spikeScore,
                seen_count: stats.seen_count || 0,
                block_count: stats.block_count || (node.global_block_count || 0),
                is_previously_blocked: stats.block_count > 0 || (node.global_block_count > 0),
                last_seen: stats.last_seen,
                network_signals: node.global_signals || []
            };
            
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
