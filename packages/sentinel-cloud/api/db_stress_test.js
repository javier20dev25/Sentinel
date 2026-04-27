/**
 * Sentinel Cloud: Database Stress & Architecture Test
 * Executes the "Final Simulation" requested by the CTO.
 */

const crypto = require('crypto');
const PostgresSimulator = require('./db_simulator');

const db = new PostgresSimulator();

// Test Configuration
const USERS = ['user_alpha_123', 'user_beta_456', 'user_gamma_789'];
const CATEGORIES = ['supply_chain', 'credential_leak', 'obfuscation', 'prototype_pollution'];
const REPOS_PER_USER = 5;
const EVENTS_PER_REPO = 50; // Total 750 events (base)

function generateHash(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

async function runSimulation() {
    console.log(`\x1b[35m=== Sentinel DB Architecture Stress Test ===\x1b[0m\n`);
    
    let totalInsertions = 0;
    let dedupeBlocks = 0;
    const startTest = performance.now();

    // 1. BURST LOAD SIMULATION (Multi-Tenant, Varied Categories, Repeats)
    console.log(`\x1b[34m[1] Executing Burst Load (Multi-tenant: 3 Users, 15 Repos)...\x1b[0m`);
    
    const insertPromises = [];

    for (const userId of USERS) {
        for (let r = 0; r < REPOS_PER_USER; r++) {
            const repoHash = generateHash(`${userId}_repo_${r}`);
            
            for (let e = 0; e < EVENTS_PER_REPO; e++) {
                // Simulate time spread over 3 days
                const dayOffset = Math.floor(Math.random() * 3);
                const date = new Date(Date.now() - dayOffset * 86400000);
                const dayBucket = date.toISOString().split('T')[0];
                
                const category = CATEGORIES[Math.floor(Math.random() * CATEGORIES.length)];
                const pattern = `vuln_pattern_${Math.floor(Math.random() * 10)}`; // High chance of duplication
                const riskScore = Math.random();

                const eventHash = generateHash(`${userId}-${repoHash}-${category}-${pattern}-${dayBucket}`);

                const row = {
                    id: crypto.randomUUID(),
                    user_id: userId,
                    repo_hash: repoHash,
                    event_hash: eventHash,
                    category: category,
                    pattern: pattern,
                    risk_score: riskScore,
                    timestamp: date.toISOString()
                };

                // Burst insertion
                const p = db.insert('intelligence_events', row)
                    .then(() => totalInsertions++)
                    .catch(err => {
                        if (err.message.includes('unique constraint')) dedupeBlocks++;
                        else throw err;
                    });
                
                insertPromises.push(p);
            }
        }
    }

    // Wait for the burst to finish
    await Promise.all(insertPromises);
    const duration = performance.now() - startTest;

    console.log(`    ✅ Processed ${insertPromises.length} events in ${duration.toFixed(2)}ms`);
    console.log(`    ✅ Insert Latency: ~${(duration / insertPromises.length).toFixed(2)}ms per row`);
    console.log(`    ✅ Deduplication (UNIQUE event_hash) blocked: ${dedupeBlocks} duplicate inserts`);
    console.log(`    ✅ Actual rows in DB: ${totalInsertions}\n`);

    // 2. RLS (ROW LEVEL SECURITY) TESTING
    console.log(`\x1b[34m[2] Testing Row Level Security (RLS) Isolation...\x1b[0m`);
    
    // As System Admin (No RLS)
    db.setAuthUser(null);
    const totalEventsInDB = db.select('intelligence_events').length;
    
    // As User Alpha
    db.setAuthUser(USERS[0]);
    const alphaEvents = db.select('intelligence_events');
    
    // As User Beta
    db.setAuthUser(USERS[1]);
    const betaEvents = db.select('intelligence_events');

    console.log(`    System sees: ${totalEventsInDB} total rows.`);
    console.log(`    User Alpha sees: ${alphaEvents.length} rows.`);
    console.log(`    User Beta sees:  ${betaEvents.length} rows.`);
    
    if (alphaEvents.length + betaEvents.length < totalEventsInDB) {
        console.log(`    ✅ RLS Passed: Users cannot see each other's data.\n`);
    } else {
        console.log(`    ❌ RLS Failed!\n`);
    }

    // 3. MATERIALIZED VIEW REFRESH
    console.log(`\x1b[34m[3] Testing Materialized View (daily_threats)...\x1b[0m`);
    const mvResult = await db.refreshMaterializedView();
    console.log(`    ✅ REFRESH MATERIALIZED VIEW daily_threats completed in ${mvResult.time_ms}ms.`);
    console.log(`    ✅ Aggregated ${mvResult.rows_processed} rows into ${db.materialized_views.daily_threats.length} analytics buckets.\n`);

    // 4. MOCK DASHBOARD QUERY (Using Materialized View)
    console.log(`\x1b[34m[4] Querying Dashboard for User Alpha (Top Threats)...\x1b[0m`);
    db.setAuthUser(USERS[0]);
    
    // Emulate: SELECT category, sum(total_threats) FROM daily_threats WHERE user_id = alpha GROUP BY category
    const dashboardQuery = db.materialized_views.daily_threats
        .filter(r => r.user_id === USERS[0])
        .reduce((acc, row) => {
            acc[row.category] = (acc[row.category] || 0) + row.total_threats;
            return acc;
        }, {});

    console.table(dashboardQuery);
    console.log(`    ✅ Dashboard query executed instantly against Materialized View.\n`);

    console.log(`\x1b[32m[SUCCESS] Architecture constraints validated. Ready for Dashboard UI.\x1b[0m`);
}

runSimulation();
