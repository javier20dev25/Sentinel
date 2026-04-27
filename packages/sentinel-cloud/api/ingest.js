/**
 * Sentinel Cloud: Intelligence Ingest API (Hardened v2.0)
 * 
 * Pipeline: INGEST -> VALIDATE AUTH -> SANITIZE -> DEDUPE -> STORE
 * Architecture: Node.js (Vercel Serverless / Express) -> Supabase
 */

const crypto = require('crypto');

// --- Mocked External Services (Supabase & Redis) ---
const Supabase = {
    insert: async (table, data) => {
        console.log(`[SUPABASE] Inserted into ${table}:`, data.id || data.event_id);
        return true;
    }
};

const RedisCache = {
    checkRateLimit: async (userId, tier) => {
        const limit = tier === 'FREE' ? 100 : 1000;
        // In reality, this would use an atomic INCR with TTL
        return { allowed: true, remaining: limit - 1 };
    },
    isDuplicate: async (hash) => {
        // Mock: Not a duplicate
        return false;
    },
    setHash: async (hash) => { return true; }
};

// --- Security Middleware ---
const Security = {
    verifyJWT: (token) => {
        // In production: jsonwebtoken.verify(token, SUPABASE_JWT_SECRET)
        // Expected payload: { sub: 'user_id', tier: 'FREE', repo_scope: ['hash1'] }
        if (!token || token !== 'mock-valid-jwt') throw new Error('Invalid JWT');
        return { sub: 'usr_12345', tier: 'FREE', repo_scope: ['abc123hash'] };
    },
    
    validatePayloadSafety: (pattern) => {
        // 1. Strict Regex (Only alphanumeric, underscore, hyphen)
        if (!/^[a-zA-Z0-9_\-]+$/.test(pattern)) return false;
        
        // 2. Block JS execution vectors (even if regex somehow fails)
        const blocklist = ['eval(', 'require(', 'Buffer(', 'function('];
        for (const blocked of blocklist) {
            if (pattern.includes(blocked)) return false;
        }
        return true;
    }
};

// --- Ingest Pipeline ---

async function ingestIntelligenceEvent(req, res) {
    try {
        // 1. VALIDATE AUTH (JWT)
        const authHeader = req.headers['authorization'];
        const token = authHeader ? authHeader.split(' ')[1] : null;
        let user;
        try {
            user = Security.verifyJWT(token);
        } catch (err) {
            return res.status(401).json({ error: 'Unauthorized: Invalid JWT signature' });
        }

        const { meta, threat, metrics, ast_features } = req.body;
        
        // Ensure the repo belongs to the user's scope
        if (!user.repo_scope.includes(meta.repo_hash)) {
            return res.status(403).json({ error: 'Forbidden: Repository not in authorized scope' });
        }

        // 2. RATE LIMIT
        const rateLimit = await RedisCache.checkRateLimit(user.sub, user.tier);
        if (!rateLimit.allowed) {
            return res.status(429).json({ error: 'Rate limit exceeded for your tier.' });
        }

        if (!meta || !threat || !meta.repo_hash) {
            return res.status(400).json({ error: 'Malformed payload contract.' });
        }

        // 3. SANITIZE
        const rawPattern = String(threat.pattern).substring(0, 50);
        if (!Security.validatePayloadSafety(rawPattern)) {
            console.warn(`[SECURITY] Blocked malicious payload attempt from ${user.sub}`);
            return res.status(400).json({ error: 'Payload rejected by security filters.' });
        }

        // 4. DEDUPLICATE (Prevent DB Spam & Granular buckets)
        // Hash: User + Repo + Category + Pattern + DayBucket
        const dayBucket = new Date().toISOString().split('T')[0];
        const dedupeString = `${user.sub}-${meta.repo_hash}-${threat.category}-${rawPattern}-${dayBucket}`;
        const eventHash = crypto.createHash('sha256').update(dedupeString).digest('hex');

        if (await RedisCache.isDuplicate(eventHash)) {
            return res.status(202).json({ status: 'ignored_duplicate' });
        }

        // 5. STORE
        const eventId = crypto.randomUUID();

        await Supabase.insert('intelligence_events', {
            id: eventId,
            user_id: user.sub,
            repo_hash: meta.repo_hash,
            event_hash: eventHash,
            category: threat.category,
            pattern: rawPattern,
            risk_score: threat.risk_score,
            confidence: threat.confidence,
            timestamp: meta.timestamp
        });

        await Supabase.insert('event_metrics', {
            event_id: eventId,
            scan_time_ms: metrics.scan_time_ms,
            files_scanned: metrics.files_scanned
        });

        if (ast_features && user.tier !== 'FREE') {
            await Supabase.insert('event_features', {
                event_id: eventId,
                entropy: ast_features.entropy,
                uses_eval: ast_features.uses_eval,
                dynamic_require: ast_features.dynamic_require
            });
        }

        await RedisCache.setHash(eventHash);

        return res.status(201).json({ status: 'ingested', event_id: eventId });

    } catch (error) {
        console.error('[INGEST ERROR]', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}

module.exports = { ingestIntelligenceEvent };

// --- Quick Test Execution ---
if (require.main === module) {
    const mockRequest = {
        headers: { 'authorization': 'Bearer mock-valid-jwt' },
        body: {
            meta: { timestamp: new Date().toISOString(), cli_version: "3.0.0", repo_hash: "abc123hash", language: "javascript", tier: "FREE" },
            threat: { category: "supply_chain", pattern: "obfuscated_install", risk_score: 0.92, confidence: 0.87 },
            metrics: { scan_time_ms: 420, files_scanned: 182 }
        }
    };
    const mockResponse = {
        status: (code) => ({ json: (data) => console.log(`HTTP ${code}:`, data) })
    };
    
    console.log("Testing Hardened Pipeline...");
    ingestIntelligenceEvent(mockRequest, mockResponse);
}
