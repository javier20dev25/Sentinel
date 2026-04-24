/**
 * Sentinel: Risk Graph Persistence Layer (v1.0)
 * 
 * Implements a directed graph for cross-repository intelligence correlation.
 * Tracks relationships between packages, repositories, signals, and decisions.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

class RiskGraph {
    constructor() {
        this.storagePath = path.join(os.homedir(), '.sentinel', 'risk_graph.json');
        this.nodes = {
            package: {},
            repository: {},
            signal: {},
            decision: {}
        };
        this.edges = [];
        this._load();
    }

    /**
     * Internal method to load the graph from disk.
     */
    _load() {
        try {
            if (fs.existsSync(this.storagePath)) {
                const data = JSON.parse(fs.readFileSync(this.storagePath, 'utf-8'));
                this.nodes = data.nodes || this.nodes;
                this.edges = data.edges || this.edges;
            }
        } catch (e) {
            // Logically silent failure, initialize empty
        }
    }

    /**
     * Persists the current graph state to the local file system.
     */
    persist() {
        try {
            const dir = path.dirname(this.storagePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            
            fs.writeFileSync(this.storagePath, JSON.stringify({
                version: '1.0',
                updated_at: new Date().toISOString(),
                nodes: this.nodes,
                edges: this.edges
            }, null, 2));
        } catch (e) {
            // Critical persistence error
        }
    }

    /**
     * Registers or updates a node in the graph.
     * @param {string} type - Entity type (package, repository, signal, decision)
     * @param {string} id - Unique identifier (e.g., package name, repo fullName)
     * @param {Object} data - Metadata associated with the node
     */
    addNode(type, id, data = {}) {
        if (!this.nodes[type]) return;

        const existing = this.nodes[type][id] || {};
        this.nodes[type][id] = {
            ...existing,
            ...data,
            last_seen: new Date().toISOString(),
            seen_count: (existing.seen_count || 0) + 1
        };
    }

    /**
     * Creates a directed edge between two nodes.
     * @param {string} from - Source node ID (type:id format)
     * @param {string} to - Destination node ID (type:id format)
     * @param {string} type - Relationship type (e.g., used_by, triggered_by)
     */
    addEdge(from, to, type) {
        // Prevent duplicate edges
        const exists = this.edges.some(e => e.from === from && e.to === to && e.type === type);
        if (exists) return;

        this.edges.push({
            from,
            to,
            type,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Retrieves all edges associated with a specific node.
     */
    getRelatedEdges(nodeId) {
        return this.edges.filter(e => e.from === nodeId || e.to === nodeId);
    }

    /**
     * Calculates reputational metrics for a package.
     */
    getPackageStats(name) {
        const node = this.nodes.package[name];
        if (!node) return { seen_count: 0, block_count: 0, risk_score: 0 };

        const relatedEdges = this.getRelatedEdges(`package:${name}`);
        const blocks = relatedEdges.filter(e => e.type === 'blocked_in').length;
        
        return {
            seen_count: node.seen_count || 0,
            block_count: blocks,
            risk_score: node.risk_score || 0,
            last_seen: node.last_seen
        };
    }

    /**
     * Identifies temporal spikes (bursts) for a specific entity.
     * @param {string} nodeId - format "type:id"
     * @param {number} windowHours - Time window in hours
     */
    getTemporalSpikes(nodeId, windowHours = 24) {
        const now = new Date();
        const cutoff = new Date(now.getTime() - windowHours * 60 * 60 * 1000);
        
        const recentEdges = this.edges.filter(e => 
            (e.from === nodeId || e.to === nodeId) && 
            new Date(e.timestamp) > cutoff
        );

        return {
            count: recentEdges.length,
            window: windowHours
        };
    }
}

module.exports = new RiskGraph();
