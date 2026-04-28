/**
 * Sentinel: Main Scanner Orchestrator (Phase 10.5 - Oracle Brain)
 */

'use strict';

const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const os = require('os');
const yaml = require('js-yaml');
const vm = require('vm');
const crypto = require('crypto');

const { detectInvisibleChars } = require('./detector_unicode');
const { detectHighEntropy } = require('./detector_entropy');
const { analyzeLifecycleScripts, analyzeTransitiveDeps } = require('./lifecycle_filter');
const { analyzeLockfile, analyzePnpmLockfile } = require('./lockfile_filter');
const { analyzeNpmrc, analyzeYarnrcYml } = require('./config_integrity');
const ConfidenceScorer = require('./confidence_scorer');
const TriggerLevelOrchestrator = require('./trigger_levels');
const { analyzeBinary } = require('./detector_binary');
const { isValidRuleFilename, isPathWithinRoot } = require('../lib/sanitizer');

// Phase 10.5 Modules
const CONFIG = require('./config');
const ScoringEngine = require('./scoring_engine');
const CacheEngine = require('./cache_engine');
const FileClassifier = require('./file_classifier');
const RiskOrchestrator = require('./risk_orchestrator');
const { signReport } = require('../lib/signature');

// Phase 10.6 AppSec Pro Modules
const ForensicAudit = require('./forensics');
const SandboxScanner = require('./sandbox');

let compiledRules = [];
const MAX_REGEX_LENGTH = 500;
const MAX_SCAN_LINES = 10000;

function loadRules() {
    compiledRules = [];
    const ruleDirs = [
        path.join(__dirname, 'rules'),
        path.join(os.homedir(), '.sentinel', 'rules')
    ];
    for (const dir of ruleDirs) {
        if (!fs.existsSync(dir)) continue;
        const files = fs.readdirSync(dir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
        for (const file of files) {
            if (!isValidRuleFilename(file)) continue;
            const resolvedPath = path.resolve(dir, file);
            if (!isPathWithinRoot(resolvedPath, dir)) continue;
            try {
                const content = fs.readFileSync(resolvedPath, 'utf8');
                const rules = yaml.load(content) || [];
                rules.forEach(rule => {
                    if (rule.pattern && rule.pattern.length <= MAX_REGEX_LENGTH) {
                        try {
                            rule.regex = new RegExp(rule.pattern, 'g');
                            compiledRules.push(rule);
                        } catch (e) {}
                    }
                });
            } catch (err) {}
        }
    }
}
try { loadRules(); } catch (e) {}

function safeRegexTest(regex, string, timeoutMs = CONFIG.PERFORMANCE.FILE_TIMEOUT_MS) {
    try {
        const context = vm.createContext({ regex, string, result: false });
        const script = new vm.Script('result = regex.test(string);');
        script.runInContext(context, { timeout: timeoutMs });
        return context.result;
    } catch (err) { return false; }
}

async function scanFile(filename, content, authorMeta = null, options = { mode: 'local' }) {
    const results = { filename, timestamp: new Date().toISOString(), alerts: [], authorMeta };
    const lines = content.split('\n');
    const linesToScan = lines.slice(0, MAX_SCAN_LINES);
    let isEarlyExit = false;
    let suspiciousActivity = false;

    // Context-aware file classification: determine which rules apply
    const ext = path.extname(filename).toLowerCase();
    const isLockfile = /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb)$/i.test(filename);
    const isConfig = ['.json', '.yml', '.yaml', '.toml', '.ini', '.npmrc', '.yarnrc'].includes(ext);
    const isEnvFile = filename.match(/\.env/i);
    // Lockfiles: NO regex rules at all (handled by specialized analyzers below)
    // Config/JSON (non-lock): only secrets rules
    // .env files: only secrets rules  
    // Code/Scripts: full rule arsenal
    const skipRegexEntirely = isLockfile;
    const secretsOnly = !isLockfile && (isConfig || isEnvFile);

    // LEVEL 1 & 2: Primary Scan (context-aware)
    if (!skipRegexEntirely) {
        linesToScan.forEach((line, index) => {
            if (isEarlyExit) return;
            if (line.length > 8192) {
                const entropyCheck = detectHighEntropy(line);
                if (entropyCheck.some(a => a.severity === 'CRITICAL')) {
                    results.alerts.push({
                        line_number: index + 1,
                        type: 'OVERSIZED_PAYLOAD_CRITICAL',
                        description: `Payload masivo (${(line.length / 1024).toFixed(1)}KB) con entropía crítica.`,
                        riskLevel: 10,
                        classification: 'SECURITY'
                    });
                    isEarlyExit = true; suspiciousActivity = true;
                }
                return;
            }
            if (line.length > 1024) suspiciousActivity = true;
            const rulesToApply = secretsOnly 
                ? compiledRules.filter(r => r.category === 'secrets')
                : compiledRules;
            rulesToApply.forEach(rule => {
                if (isEarlyExit) return;
                try {
                    rule.regex.lastIndex = 0;
                    const isMatch = line.length < 1024 ? rule.regex.test(line) : safeRegexTest(rule.regex, line);
                    if (isMatch) {
                        suspiciousActivity = true;
                        results.alerts.push({
                            line_number: index + 1,
                            type: rule.id,
                            description: rule.description,
                            riskLevel: rule.severity,
                            classification: 'SECURITY'
                        });
                    }
                } catch (e) { }
            });
        });
    }

    results.alerts.push(...detectInvisibleChars(content).map(a => ({ ...a, classification: 'SECURITY' })));

    // LEVEL 3: Activation of Deep Detectors (Conditional)
    if (suspiciousActivity && !isEarlyExit) {
        const entropyAlerts = detectHighEntropy(content);
        entropyAlerts.forEach(a => results.alerts.push({
            line_number: a.line,
            type: a.type,
            description: a.message,
            riskLevel: a.severity === 'CRITICAL' ? 10 : 7,
            classification: 'OBFUSCATION'
        }));
        const isCode = filename.match(/\.(js|ts)$/i);
        if (isCode) {
            try {
                const scorer = new ConfidenceScorer();
                const orchestrator = new TriggerLevelOrchestrator(scorer);
                orchestrator.analyze(content, filename);
                results.alerts.push(...scorer.evaluateAll().map(t => ({ ...t, classification: 'SECURITY' })));
            } catch (e) {}
        }
    }

    if (filename.match(/(package\.json|pnpm-lock\.yaml|yarn\.lock)$/i)) {
        results.alerts.push(...analyzeLifecycleScripts(content, authorMeta).map(a => ({ ...a, classification: 'POLICY' })));
    }
    if (filename.match(/package-lock\.json$/i)) {
        results.alerts.push(...analyzeLockfile(content, null).map(a => ({ ...a, classification: 'POLICY' })));
        results.alerts.push(...analyzeTransitiveDeps(content, authorMeta).map(a => ({ ...a, classification: 'POLICY' })));
    }
    return results;
}

async function scanDirectory(dirPath, repoId = null, depth = 10, options = { mode: 'local', profile: 'DEFAULT' }) {
    const startTime = Date.now();
    const profile = CONFIG.PROFILES[options.profile] || CONFIG.PROFILES.DEFAULT;
    const absRoot = path.resolve(dirPath);
    const results = { 
        threats: 0, 
        filesScanned: 0, 
        skipped: { binary: 0, excluded: 0, large: 0, unsupported: 0, cached: 0 }, 
        rawAlerts: [], 
        performance: { startTime, durationMs: 0, filesPerSec: 0 },
        riskScore: 0,
        verdict: 'SAFE'
    };

    const fileQueue = [];
    async function collectFiles(currentPath, currentDepth) {
        if (currentDepth < 0) return;
        if (!FileClassifier.isPathSafe(currentPath, absRoot)) return;
        const items = await fsPromises.readdir(currentPath).catch(() => []);
        await Promise.all(items.map(async (item) => {
            if (profile.excludedDirs.includes(item)) { results.skipped.excluded++; return; }
            const fullPath = path.join(currentPath, item);
            const stats = await fsPromises.lstat(fullPath).catch(() => null);
            if (!stats || stats.isSymbolicLink()) return;
            if (stats.isDirectory()) await collectFiles(fullPath, currentDepth - 1);
            else if (stats.isFile()) fileQueue.push({ fullPath, item, stats });
        }));
    }
    await collectFiles(absRoot, depth);

    const fileRisks = [];
    const limit = Math.min(8, CONFIG.PERFORMANCE.CONCURRENCY_LIMIT);
    let running = 0, index = 0;

    return new Promise((resolve) => {
        async function runNext() {
            if (index >= fileQueue.length) {
                if (running === 0) {
                    results.performance.durationMs = Date.now() - startTime;
                    results.performance.filesPerSec = Math.round((results.filesScanned / (results.performance.durationMs / 1000)) || 0);

                    // DEDUPLICATION: Consolidate repeated findings (same file + same rule = 1 alert)
                    const deduped = new Map();
                    for (const alert of results.rawAlerts) {
                        const key = `${alert._file || alert.filename}::${alert.type}`;
                        if (deduped.has(key)) {
                            deduped.get(key).occurrences++;
                        } else {
                            deduped.set(key, { ...alert, occurrences: 1 });
                        }
                    }
                    results.rawAlerts = Array.from(deduped.values()).map(a => {
                        if (a.occurrences > 1) {
                            a.description = `${a.description} [Detected ${a.occurrences} times]`;
                        }
                        return a;
                    });
                    results.threats = results.rawAlerts.length;

                    results.riskScore = ScoringEngine.calculateGlobalScore(fileRisks);
                    results.verdict = results.riskScore > 0.8 ? 'CRITICAL' : (results.riskScore > 0.4 ? 'SUSPICIOUS' : 'SAFE');
                    
                    // AppSec Pro: Forensic Enrichment
                    if (options.forensics && fs.existsSync(path.join(absRoot, '.git'))) {
                        const alertsToEnrich = results.rawAlerts.slice(0, 50);
                        console.log(`[FORENSICS] Enriching up to ${alertsToEnrich.length} alerts (Cap applied)...`);
                        let enrichedCount = 0;
                        for (const alert of alertsToEnrich) {
                            if (alert.line_number && alert._fullPath) {
                                const relPath = path.relative(absRoot, alert._fullPath);
                                const forensicData = ForensicAudit.blame(absRoot, relPath, alert.line_number);
                                if (!forensicData.error) {
                                    alert.forensics = forensicData;
                                    enrichedCount++;
                                }
                            }
                        }
                        console.log(`[FORENSICS] Completed. Enriched: ${enrichedCount}`);
                    }

                    CacheEngine.save();
                    resolve(results);
                }
                return;
            }
            const { fullPath, item, stats } = fileQueue[index++];
            running++;
            try {
                const category = FileClassifier.classify(item, fullPath);
                if (profile.allowedCategories.includes(category) && stats.size <= profile.maxFileSize) {
                    const cached = CacheEngine.isValid(fullPath, stats);
                    if (cached) {
                        results.skipped.cached++; results.filesScanned++; 
                        const enrichedCached = cached.map(a => ({ ...a, _file: item, _fullPath: fullPath }));
                        results.rawAlerts.push(...enrichedCached);
                        fileRisks.push(ScoringEngine.calculateFileRisk(enrichedCached, fullPath));
                    } else {
                        let currentAlerts = [];
                        if (category === 'BINARY') {
                            const buf = await fsPromises.readFile(fullPath);
                            currentAlerts = analyzeBinary(buf, item);
                        } else {
                            const content = await fsPromises.readFile(fullPath, 'utf8');
                            const scan = await scanFile(item, content, null, options);
                            currentAlerts = scan.alerts;
                            CacheEngine.update(fullPath, stats, currentAlerts);
                        }
                        currentAlerts.forEach(a => results.rawAlerts.push({ ...a, _file: item, _fullPath: fullPath }));
                        results.threats += currentAlerts.length;
                        results.filesScanned++;
                        fileRisks.push(ScoringEngine.calculateFileRisk(currentAlerts, fullPath));
                    }
                } else { if (category === 'BINARY') results.skipped.binary++; else results.skipped.large++; }
            } catch (e) {}
            running--; runNext();
        }
        const startLimit = Math.min(limit, fileQueue.length);
        if (startLimit === 0) resolve(results);
        else for (let i = 0; i < startLimit; i++) runNext();
    });
}

function generateHardenedFingerprint(dirPath) {
    try {
        const items = fs.readdirSync(dirPath).filter(f => !['node_modules', '.git'].includes(f)).sort();
        const components = items.slice(0, 50).map(item => {
            const stats = fs.lstatSync(path.join(dirPath, item));
            return `${item}:${stats.size}`;
        });
        return crypto.createHash('sha256').update(components.join('|')).digest('hex');
    } catch (err) { return 'deadbeef'; }
}

function finalizeVerdict(results, externalSignals = [], profile = 'balanced', oracleCtx = {}) {
    results.scan_id = crypto.randomBytes(8).toString('hex');
    const allSignals = [...(results.rawAlerts || []), ...externalSignals];
    results.rawAlerts.forEach(a => { if (!a.source) a.source = 'internal'; });
    const decision = RiskOrchestrator.arbitrate(allSignals, profile, oracleCtx);
    Object.assign(results, {
        decisionVerdict: decision.decision,
        riskScore: decision.score,
        riskBand: decision.riskBand,
        decisionConfidence: decision.decisionConfidence,
        isAuthorized: decision.isAuthorized,
        trustLevel: decision.trustLevel,
        rationale: decision.rationale,
        activeProfile: profile,
        traceId: decision.traceId,
        probingIntensity: decision.probingIntensity,
        delayMs: decision.delayMs
    });
    const { signature, tier } = signReport(results, process.env.SENTINEL_LICENSE_KEY || null);
    results.report_signature = signature; results.verification_tier = tier;
    return results;
}

function logScanAudit(context) {
    const event = { event: 'scan_completed', timestamp: new Date().toISOString(), ...context };
    try {
        const auditPath = path.join(os.homedir(), '.sentinel', 'sentinel-audit.jsonl');
        fs.appendFileSync(auditPath, JSON.stringify(event) + '\n');
    } catch (err) {}
    return event;
}

async function auditWithSurgicalSandbox(repoPath, options = { profile: 'BALANCED' }) {
    console.log(`\n\x1b[34m[APPSEC-PRO] Starting Surgical Sandbox Audit for: ${repoPath}\x1b[0m`);
    
    // 1. Fast Static Sweep
    console.log(`  -> [PHASE 1] Executing Static Heuristics...`);
    const staticResults = await scanDirectory(repoPath, null, 3, { ...options, forensics: false });
    
    console.log(`  -> [PHASE 1] Static Verdict: ${staticResults.verdict} (Score: ${staticResults.riskScore.toFixed(2)})`);

    // 2. Surgical Auto-Trigger
    if (staticResults.riskScore >= 0.60) {
        console.log(`  -> \x1b[31m[TRIGGER] Risk threshold exceeded (>= 0.60). Activating Docker Sandbox...\x1b[0m`);
        const sandboxResult = await SandboxScanner.scanSupplyChain(repoPath);
        
        staticResults.sandbox_triggered = true;
        
        if (!sandboxResult.success) {
            console.log(`  -> [PHASE 2] Sandbox Error: ${sandboxResult.error}`);
            staticResults.sandbox_execution_success = false;
        } else {
            console.log(`  -> [PHASE 2] Sandbox Execution Captured Successfully.`);
            staticResults.sandbox_execution_success = true;
            // In a full implementation, we would analyze the container logs (e.g. syscalls, network output)
            staticResults.sandbox_output_snippet = sandboxResult.output ? sandboxResult.output.substring(0, 500) : '';
        }
    } else {
        console.log(`  -> \x1b[32m[PASS] Risk is acceptable. Bypassing Sandbox Execution.\x1b[0m`);
        staticResults.sandbox_triggered = false;
    }

    return staticResults;
}

module.exports = { 
    scanFile, 
    scanLocalFile: (p, c, o) => scanFile(path.basename(p), c, null, o), 
    scanDirectory, 
    auditWithSurgicalSandbox, // Phase 5 Surgical Sandbox Auto-Trigger
    loadRules, 
    finalizeVerdict, 
    generateHardenedFingerprint, 
    logScanAudit 
};
