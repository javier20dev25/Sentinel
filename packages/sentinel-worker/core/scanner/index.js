/**
 * Sentinel: Main Scanner Orchestrator (v6.5 - Hero Mode)
 */

'use strict';

const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const os = require('os');
const yaml = require('js-yaml');
const vm = require('vm');
const crypto = require('crypto');

const { detectInvisibleChars } = require('./detectors/unicode');
const { detectHighEntropy } = require('./detectors/entropy');
const { analyzeLifecycleScripts, analyzeTransitiveDeps } = require('./lifecycle_filter');
const { analyzeLockfile } = require('./lockfile_filter');
const ScoringEngine = require('./scoring_engine');
const RiskOrchestrator = require('./risk_orchestrator');
const SemanticNormalizer = require('./semantic_normalizer');

let compiledRules = [];

function mapIntent(type) {
    if (!type) return 'POLICY_VIOLATION';
    const upType = type.toUpperCase();
    if (upType.includes('EXEC') || upType.includes('PROCESS') || upType.includes('SHELL') || upType.includes('SPAWN')) return 'EXECUTION';
    if (upType.includes('SECRET') || upType.includes('KEY') || upType.includes('ENV') || upType.includes('TOKEN')) return 'EXFILTRATION';
    if (upType.includes('OBFUSCATION') || upType.includes('ENTROPY') || upType.includes('BASE64') || upType.includes('EVASION') || upType.includes('RECONSTRUCTION')) return 'OBFUSCATION';
    if (upType.includes('LIFECYCLE') || upType.includes('INSTALL') || upType.includes('DEPENDENCY')) return 'SUPPLY_CHAIN_TAMPERING';
    if (upType.includes('NETWORK') || upType.includes('FETCH') || upType.includes('HTTP') || upType.includes('HTTPS')) return 'NETWORK';
    if (upType.includes('CI') || upType.includes('WORKFLOW')) return 'CI_CD_ABUSE';
    return 'POLICY_VIOLATION';
}

function loadRules() {
    compiledRules = [];
    const dir = path.join(__dirname, 'rules');
    if (fs.existsSync(dir)) {
        fs.readdirSync(dir).filter(f => f.endsWith('.yaml')).forEach(file => {
            try {
                const rules = yaml.load(fs.readFileSync(path.join(dir, file), 'utf8')) || [];
                rules.forEach(rule => {
                    if (rule.pattern) {
                        rule.regex = new RegExp(rule.pattern, 'g');
                        compiledRules.push(rule);
                    }
                });
            } catch (err) {}
        });
    }
}
try { loadRules(); } catch (e) {}

const CapabilityGraph = require('./capability_graph');

async function scanFile(filename, content, authorMeta = null, options = { mode: 'local' }) {
    const results = { filename, timestamp: new Date().toISOString(), alerts: [], authorMeta };
    
    // 1. Capability Graph Trace (v6.9 - Sovereign)
    const capabilities = CapabilityGraph.trace(content);
    capabilities.paths.forEach(p => {
        const evidenceArr = [p.origin, ...p.intermediate, p.destination];
        if (p.isHeuristic) evidenceArr.unshift('[HEURISTIC]');
        
        results.alerts.push({
            type: `CAPABILITY_CHAIN`,
            description: `Detected dangerous capability flow: ${p.origin} -> ${p.destination}`,
            riskLevel: p.severity,
            classification: 'SECURITY',
            evidence: evidenceArr,
            heuristicReasons: p.heuristicReasons || null
        });
    });

    const lines = content.split('\n').slice(0, 10000);
    let suspiciousActivity = false;

    // 1. Regex Rule Matching
    lines.forEach((line, index) => {
        compiledRules.forEach(rule => {
            rule.regex.lastIndex = 0;
            if (rule.regex.test(line)) {
                suspiciousActivity = true;
                results.alerts.push({
                    line_number: index + 1,
                    type: rule.id,
                    description: rule.description,
                    riskLevel: rule.severity,
                    classification: 'SECURITY',
                    line: line.trim().substring(0, 500)
                });
            }
        });
    });

    // 2. SEMANTIC INTENT ANALYSIS (v6.6)
    const semanticNodes = SemanticNormalizer.analyze(content);
    semanticNodes.forEach(node => {
        suspiciousActivity = true;
        results.alerts.push({
            type: `SEMANTIC_${node}`,
            description: `Normalized semantic intent detected: ${node}`,
            riskLevel: 8,
            classification: 'SECURITY',
            intent: mapIntent(`SEMANTIC_${node}`)
        });
    });

    // 3. TAINT-LITE / COORDINATION ANALYSIS (v6.6)
    const isSecretAccess = semanticNodes.includes('SECRET_ACCESS') || content.includes('process.env');
    const isNetworkAccess = semanticNodes.includes('NETWORK_CAPABILITY') || content.includes('fetch') || content.includes('require(\'https\')');
    
    if (isSecretAccess && isNetworkAccess) {
        results.alerts.push({
            type: 'COORDINATED_NETWORK_EXFIL',
            description: 'Detected suspicious coordination between sensitive data access and network exfiltration capabilities.',
            riskLevel: 10,
            classification: 'SECURITY',
            intent: 'EXFILTRATION'
        });
    }

    // 4. Obfuscation & Entropy
    if (suspiciousActivity || content.length > 5000) {
        const entropyAlerts = detectHighEntropy(content);
        entropyAlerts.forEach(a => results.alerts.push({
            line_number: a.line,
            type: a.type,
            description: a.message,
            riskLevel: a.severity === 'CRITICAL' ? 10 : 7,
            classification: 'OBFUSCATION',
            intent: 'OBFUSCATION'
        }));
    }

    results.alerts.push(...detectInvisibleChars(content).map(a => ({ ...a, classification: 'SECURITY', intent: 'OBFUSCATION' })));

    if (filename.match(/(package\.json|pnpm-lock\.yaml|yarn\.lock)$/i)) {
        results.alerts.push(...analyzeLifecycleScripts(content, authorMeta).map(a => ({ ...a, classification: 'POLICY', intent: 'SUPPLY_CHAIN_TAMPERING' })));
    }

    // Ensure all alerts have an intent
    results.alerts.forEach(a => {
        if (!a.intent) a.intent = mapIntent(a.type);
    });

    return results;
}

async function scanDirectory(dirPath, repoId = null, depth = 5, options = { mode: 'local', profile: 'DEFAULT' }) {
    const absRoot = path.resolve(dirPath);
    const results = { threats: 0, filesScanned: 0, rawAlerts: [], riskScore: 0 };
    const fileQueue = [];

    async function collect(currentPath, d) {
        if (d < 0) return;
        const items = await fsPromises.readdir(currentPath).catch(() => []);
        for (const item of items) {
            if (item === 'node_modules' || item === '.git') continue;
            const fullPath = path.join(currentPath, item);
            const stats = await fsPromises.lstat(fullPath).catch(() => null);
            if (!stats) continue;
            if (stats.isDirectory()) await collect(fullPath, d - 1);
            else if (stats.isFile()) fileQueue.push({ fullPath, item, stats });
        }
    }
    await collect(absRoot, depth);

    for (const file of fileQueue) {
        results.filesScanned++;
        const content = await fsPromises.readFile(file.fullPath, 'utf8').catch(() => null);
        if (!content) continue;
        const scan = await scanFile(file.item, content, null, options);
        const enriched = scan.alerts.map(a => ({
            ...a,
            _file: file.item,
            _fullPath: file.fullPath,
            intent: mapIntent(a.type),
            confidence: 0.6
        }));
        results.rawAlerts.push(...enriched);
    }
    results.threats = results.rawAlerts.length;
    return results;
}

function finalizeVerdict(results, externalSignals = [], profile = 'balanced', oracleCtx = {}) {
    results.scan_id = crypto.randomBytes(8).toString('hex');
    results.rawAlerts = results.rawAlerts || results.alerts || [];
    const allSignals = [...results.rawAlerts, ...externalSignals];
    allSignals.forEach(a => { 
        if (!a.source) a.source = 'internal'; 
        if (!a.file && !a._file && !a._fullPath && results.filename) a.file = results.filename;
    });
    
    // Ensure Repo ID Persistence for Slow Poisoning
    const repoId = oracleCtx.repoId || results.repoId || 'global-unassigned';
    
    const decision = RiskOrchestrator.arbitrate(allSignals, profile, { 
        ...oracleCtx, 
        repoId,
        mode: results.mode || 'REPO' 
    });

    // --- CLEAN OUTPUT (no more schema drift) ---
    // Canonical fields: verdict, impactScore, decisionConfidence, fingerprint
    // Everything else is internal/trace-only
    const evidenceGraph = allSignals.filter(s => s.type === 'CAPABILITY_CHAIN').map(s => {
        let trace = s.evidence.join(' → ');
        if (s.heuristicReasons && s.heuristicReasons.length > 0) {
            const reasonsStr = s.heuristicReasons.map(r => `${r.signal} (wt: ${r.weight})`).join(' | ');
            trace += ` (Reasons: ${reasonsStr})`;
        }
        return trace;
    });

    Object.assign(results, {
        // --- CANONICAL (frozen) ---
        verdict: decision.verdict,
        impactScore: decision.impactScore,
        decisionConfidence: decision.decisionConfidence,
        fingerprint: decision.fingerprint,
        traceId: decision.traceId,
        
        // --- LEGACY COMPAT (deprecated, downstream should use canonical) ---
        impact: decision.impactScore,
        riskScore: decision.impactScore,

        // --- FORENSIC ---
        reasoningTrace: decision.reasoningTrace,
        rationale: decision.rationale,
        metrics: decision.metrics,
        evidenceGraph
    });
    return results;
}

function generateHardenedFingerprint(dirPath) {
    return crypto.createHash('sha256').update(dirPath).digest('hex');
}

module.exports = { 
    scanFile, 
    scanDirectory, 
    finalizeVerdict, 
    generateHardenedFingerprint,
    loadRules 
};
