/**
 * Sentinel: Dependency Trust Engine (v3.0 — Adapter Architecture)
 * 
 * Core dispatcher. Delegates ecosystem-specific analysis to registered adapters.
 * Trust Cache, Scoring, and Policy remain centralized here.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

// ─── Adapter Registry ────────────────────────────────────────────────────────
const ADAPTERS = {
    npm:    require('./adapters/npm_adapter'),
    yarn:   require('./adapters/npm_adapter'),   // alias
    pnpm:   require('./adapters/npm_adapter'),   // alias
    pip:    require('./adapters/pip_adapter'),
    pip3:   require('./adapters/pip_adapter'),   // alias
    docker: require('./adapters/docker_adapter'),
    // Future: cargo, apt, brew, choco
};

// ─── Trust Cache ─────────────────────────────────────────────────────────────
const SENTINEL_DIR   = path.join(os.homedir(), '.sentinel');
const TRUST_CACHE_PATH = path.join(SENTINEL_DIR, 'trust-cache.json');

class TrustCache {
    constructor() { this._cache = this._load(); }

    _load() {
        try {
            if (!fs.existsSync(SENTINEL_DIR)) fs.mkdirSync(SENTINEL_DIR, { recursive: true });
            if (fs.existsSync(TRUST_CACHE_PATH)) return JSON.parse(fs.readFileSync(TRUST_CACHE_PATH, 'utf8'));
        } catch (e) {}
        return {};
    }

    _save() {
        try { fs.writeFileSync(TRUST_CACHE_PATH, JSON.stringify(this._cache, null, 2)); } catch (e) {}
    }

    _key(adapter, pkg) { return `${adapter}:${pkg}`; }
    get(adapter, pkg)  { return this._cache[this._key(adapter, pkg)] || null; }

    set(adapter, pkg, verdict, signals = []) {
        this._cache[this._key(adapter, pkg)] = {
            verdict, signals: signals.length, ts: Date.now(),
            hash: crypto.createHash('md5').update(`${adapter}:${pkg}:${verdict}`).digest('hex').slice(0, 8)
        };
        this._save();
    }

    markTrusted(adapter, pkg) { this.set(adapter, pkg, 'TRUSTED'); }
    markBlocked(adapter, pkg) { this.set(adapter, pkg, 'BLOCKED'); }
    isExpired(entry) { return Date.now() - entry.ts > 7 * 24 * 60 * 60 * 1000; }
    all() { return this._cache; }
}

const trustCache = new TrustCache();

// ─── Core Scoring ─────────────────────────────────────────────────────────────
function levenshtein(a, b) {
    const m = [];
    for (let i = 0; i <= b.length; i++) m[i] = [i];
    for (let j = 0; j <= a.length; j++) m[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b[i - 1] === a[j - 1]) m[i][j] = m[i - 1][j - 1];
            else m[i][j] = Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1);
        }
    }
    return m[b.length][a.length];
}

function checkTyposquatting(adapter, pkgName) {
    const protectedList = adapter.protected || [];
    const base = pkgName.replace(/^@[^/]+\//, '').replace(/[-_.]/g, '').toLowerCase();

    for (const protectedPkg of protectedList) {
        if (pkgName === protectedPkg) return null;
        const target = protectedPkg.replace(/[-_.]/g, '').toLowerCase();
        const distance = levenshtein(base, target);
        if (distance <= 1 || (distance === 2 && base.length >= 5)) {
            return { type: 'TYPOSQUATTING_ATTEMPT', target: protectedPkg, distance };
        }
    }

    // Adapter-specific scope abuse check
    if (adapter.checkScopeAbuse) return adapter.checkScopeAbuse(pkgName);
    return null;
}

function calcRiskScore(typo, lifecycleFindings, reputationSignals) {
    let score = 0;
    if (typo) score += typo.type === 'TYPOSQUATTING_ATTEMPT' ? 0.95 : 0.80;
    for (const f of lifecycleFindings) score += f.severity === 'MALICIOUS' ? 0.90 : 0.40;
    for (const s of (reputationSignals || [])) score += s.riskLevel || 0;
    return Math.min(1.0, score);
}

// ─── Main Dispatcher ──────────────────────────────────────────────────────────
class SupplyChainShield {

    static getAdapter(adapterName) {
        const adapter = ADAPTERS[adapterName?.toLowerCase()];
        if (!adapter) throw new Error(`Unsupported ecosystem: '${adapterName}'. Supported: ${Object.keys(ADAPTERS).join(', ')}`);
        return adapter;
    }

    static getTrustCache() { return trustCache; }
    static listAdapters()  { return [...new Set(Object.values(ADAPTERS).map(a => a.id))]; }

    static async preScanManifest(adapterName, pkgName, rawManifest = {}) {
        const adapter = SupplyChainShield.getAdapter(adapterName);

        // 1. Trust Cache (instant path)
        const cached = trustCache.get(adapterName, pkgName);
        if (cached && !trustCache.isExpired(cached)) {
            return { packageName: pkgName, adapter: adapterName, ecosystemId: adapter.id,
                     riskScore: cached.verdict === 'TRUSTED' ? 0 : 0.9,
                     verdict: cached.verdict, signals: [], fromCache: true, cacheHash: cached.hash };
        }

        const signals = [];

        // 2. Typosquatting (all adapters)
        const typo = checkTyposquatting(adapter, pkgName);
        if (typo) signals.push({ type: 'INTENT_MALICIOUS', category: 'typosquatting',
            description: `'${typo.type}' against protected package '${typo.target}'.`, riskLevel: 0.95 });

        // 3. Lifecycle / Manifest audit (adapter-specific)
        const parsed = adapter.parseManifest(rawManifest);
        const scriptFindings = adapter.auditScripts(parsed.scripts);
        for (const f of scriptFindings) {
            signals.push({ type: f.severity === 'MALICIOUS' ? 'INTENT_MALICIOUS' : 'BEHAVIOR_SUSPICIOUS',
                category: f.category, description: `${f.severity} behavior in '${f.hook}' hook.`,
                riskLevel: f.severity === 'MALICIOUS' ? 0.90 : 0.55 });
        }

        // 4. Adapter-specific extra signals (e.g. Docker image classification)
        let extraSignals = [];
        if (adapter.getDockerSignals) {
            const { signals: ds } = adapter.getDockerSignals(pkgName);
            extraSignals = ds;
            signals.push(...ds);
        }

        // 5. Reputation (simulated; real: call registry API)
        const isKnown = (adapter.protected || []).includes(pkgName);
        if (!isKnown && adapter.id !== 'docker') {
            const ageDays = 3; // stub
            if (ageDays < 30) {
                signals.push({ type: 'BEHAVIOR_SUSPICIOUS', category: 'low_reputation',
                    description: `'${pkgName}' appears to be a new or low-visibility package.`, riskLevel: 0.35 });
            }
        }

        const riskScore = calcRiskScore(typo, scriptFindings, extraSignals);
        const verdict = riskScore >= 0.85 ? 'BLOCK' : (riskScore >= 0.40 ? 'SUSPICIOUS' : 'SAFE');

        trustCache.set(adapterName, pkgName, verdict, signals);
        return { packageName: pkgName, adapter: adapterName, ecosystemId: adapter.id, riskScore, signals, verdict, fromCache: false };
    }

    static generateSandboxWorkflow(adapterName, pkgName) {
        const cmds = { npm: `npm install ${pkgName}`, pip: `pip install ${pkgName}`,
                       docker: `docker pull ${pkgName}` };
        const run = cmds[adapterName] || `echo "Unsupported adapter: ${adapterName}"`;
        return `name: Sentinel Package Sandbox Verification\non: workflow_dispatch\njobs:\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Behavioral Observation\n        run: |\n          ${run}\n      - uses: actions/upload-artifact@v3\n        with:\n          name: sentinel-sandbox-report\n          path: sentinel-report.json`;
    }

    static executeInstall(adapterName, pkgName, extraArgs = []) {
        const adapter = SupplyChainShield.getAdapter(adapterName);
        const { buildSpawnConfig } = require('../lib/cmd_resolver');
        const [basecmd, baseArgs] = adapter.installCmd(pkgName, extraArgs);
        const { cmd, args, options } = buildSpawnConfig(basecmd, baseArgs);
        console.log(`\n\u{1F680} Policy Authorized. Executing: ${cmd} ${args.join(' ')}`);
        return spawn(cmd, args, options);
    }
}

module.exports = SupplyChainShield;
