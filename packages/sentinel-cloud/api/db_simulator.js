/**
 * Sentinel Cloud: Local Supabase / PostgreSQL Simulator
 * Validates the Schema constraints (RLS, Unique Hashes, MV Refresh)
 * Designed for Stress Testing before production deployment.
 */

const crypto = require('crypto');

class PostgresSimulator {
    constructor() {
        this.tables = {
            intelligence_events: new Map(), // O(1) Indexing on ID
            event_metrics: new Map()
        };
        this.indexes = {
            event_hash: new Set() // Simulates UNIQUE INDEX
        };
        this.materialized_views = {
            daily_threats: []
        };
        this.auth_context = null; // Simulates auth.uid()
    }

    setAuthUser(userId) {
        this.auth_context = userId;
    }

    // Simulates RLS Policies for SELECT
    select(table, conditions = {}) {
        let results = Array.from(this.tables[table].values());
        
        // RLS Enforcement: "Users see their own events"
        if (table === 'intelligence_events' && this.auth_context) {
            results = results.filter(row => row.user_id === this.auth_context);
        }

        // Apply where conditions
        for (const [key, value] of Object.entries(conditions)) {
            results = results.filter(row => row[key] === value);
        }
        return results;
    }

    // Simulates INSERT with UNIQUE constraint
    async insert(table, row) {
        // Simulate Network/Disk Latency (1-3ms)
        await new Promise(r => setTimeout(r, Math.random() * 2 + 1));

        if (table === 'intelligence_events') {
            // Check UNIQUE event_hash
            if (this.indexes.event_hash.has(row.event_hash)) {
                throw new Error(`duplicate key value violates unique constraint "intelligence_events_event_hash_key"`);
            }
            
            // Calculate computed column 'risk_level'
            if (row.risk_score >= 0.80) row.risk_level = 'CRITICAL';
            else if (row.risk_score >= 0.60) row.risk_level = 'HIGH';
            else if (row.risk_score >= 0.30) row.risk_level = 'MEDIUM';
            else row.risk_level = 'LOW';

            this.indexes.event_hash.add(row.event_hash);
        }

        this.tables[table].set(row.id, row);
        return row;
    }

    // Simulates REFRESH MATERIALIZED VIEW
    async refreshMaterializedView() {
        const start = performance.now();
        const agg = {};

        for (const event of this.tables.intelligence_events.values()) {
            const day = event.timestamp.split('T')[0];
            const key = `${day}_${event.user_id}_${event.category}`;
            
            if (!agg[key]) {
                agg[key] = { day, user_id: event.user_id, category: event.category, total_threats: 0, sum_risk: 0 };
            }
            agg[key].total_threats++;
            agg[key].sum_risk += event.risk_score;
        }

        this.materialized_views.daily_threats = Object.values(agg).map(row => ({
            ...row,
            avg_risk: row.sum_risk / row.total_threats
        }));

        const duration = performance.now() - start;
        return { rows_processed: this.tables.intelligence_events.size, time_ms: duration.toFixed(2) };
    }
}

module.exports = PostgresSimulator;
